package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * B13 (2026-08-30 PR #25 review fix) - the ONE place NovaXrayVpnService's
 * per-endpoint controller selection AND its requestStart/requestStop calls
 * are serialized. Extracted as its own plain-JVM-testable class - the same
 * reasoning [XrayCoreController]/[XrayServiceLifecycleGate] already
 * establish (this project has no Robolectric dependency) - specifically so
 * the race this class exists to close can be proven closed with a real
 * [Mutex] under real coroutine interleaving in a test
 * ([NovaXrayServiceLifecycleCoordinatorTest]), not asserted from a
 * misleading "single-threaded Binder path" assumption. That assumption WAS
 * wrong: `startIfNotAlreadyRunning` runs inside `scope.launch` on
 * `Dispatchers.IO`, so two near-simultaneous ACTION_START intents can genuinely
 * run their handling concurrently - `onStartCommand` merely SCHEDULES that
 * work, it does not serialize it, and `@Volatile` alone only makes each
 * individual field read/write atomic, never the compound
 * check-cached-controller-then-build-then-publish sequence as a whole.
 *
 * [controllerFactory] builds a fresh [XrayCoreController] for a given
 * endpoint - called only while [mutex] is held, so two concurrent builds for
 * the SAME endpoint can never race, and a build for a NEW endpoint always
 * happens strictly after any previous endpoint's controller has been told to
 * stop (see [selectControllerLocked]).
 */
class NovaXrayServiceLifecycleCoordinator(
    private val controllerFactory: (EndpointId) -> XrayCoreController,
) {
    private val mutex = Mutex()
    private var controllerEndpointId: EndpointId? = null
    private var cachedController: XrayCoreController? = null

    /**
     * Selects (reusing the cached instance for the SAME endpoint) or builds
     * (for a DIFFERENT endpoint, after an authoritative [XrayCoreController.requestStop]
     * of whatever was cached before) the correct controller, THEN calls
     * [XrayCoreController.requestStart] on it - all under ONE lock
     * acquisition, so no concurrent [start]/[stop] call can ever observe or
     * act on an intermediate state (e.g. a controller that has been selected
     * but not yet told to start). Preserves [XrayCoreController]'s own
     * AlreadyRunning/StartInFlight semantics for repeated calls against the
     * SAME endpoint - its `lifecycleGate` lives on the SAME cached instance
     * across such calls, never rebuilt merely because [start] was called
     * again.
     *
     * Held for the FULL duration of [XrayCoreController.requestStart] -
     * including tun establishment and native core startup - deliberately: a
     * concurrent [start] for a different endpoint, or a concurrent [stop],
     * must wait for this attempt to genuinely finish (success or failure)
     * before acting, rather than racing it. This mirrors how this work was
     * already async/non-blocking from the calling Service's perspective
     * before this fix (see `NovaXrayVpnService.startIfNotAlreadyRunning`'s
     * own `scope.launch` wrapper) - only concurrent callers of THIS class
     * now queue behind each other, never the Service's own onStartCommand.
     */
    // B18-2 - [routingMode] defaults to FULL_VPN, same reasoning as
    // XrayCoreController.requestStart's own default - every pre-B18-2 caller
    // is byte-for-byte unaffected.
    // B33 relay follow-up - [confirmationContext] defaults to
    // [RemoteConfirmationContext.Direct], same reasoning -
    // every pre-existing caller is byte-for-byte unaffected; NovaXrayVpnService
    // is the one real caller that supplies a Relayed value.
    suspend fun start(
        endpointId: EndpointId,
        kind: TransportKind,
        routingMode: RoutingMode = RoutingMode.FULL_VPN,
        confirmationContext: RemoteConfirmationContext = RemoteConfirmationContext.Direct,
    ): XrayCoreStartOutcome = mutex.withLock {
        selectControllerLocked(endpointId).requestStart(kind, routingMode, confirmationContext)
    }

    /**
     * Tears down whatever is CURRENTLY cached (any endpoint) - the same
     * serialization guarantee as [start]: a stop can never observe/act on a
     * controller a concurrent start is still in the middle of
     * selecting/building/starting, and a start can never begin while a stop
     * is still running. A `didTeardown=false` outcome when nothing has EVER
     * been cached is the SAME "not running" no-op every other case already
     * produces - callers treat it identically.
     */
    suspend fun stop(): XrayCoreStopOutcome = mutex.withLock {
        cachedController?.requestStop() ?: XrayCoreStopOutcome(didTeardown = false)
    }

    /** Caller must already hold [mutex]. */
    private fun selectControllerLocked(endpointId: EndpointId): XrayCoreController {
        cachedController?.let { existing ->
            if (controllerEndpointId == endpointId) return existing
            // Authoritative teardown of the OLD endpoint's controller BEFORE
            // this new one is even constructed - endpoint B can never start
            // while endpoint A's own session is still considered active by
            // this coordinator. A's requestStop() outcome is irrelevant here
            // (a not-running A is a harmless no-op, same as every other
            // "nothing to tear down" case) - what matters is that this call
            // always happens, and always completes, before B's controller
            // is built, under the SAME lock.
            existing.requestStop()
        }
        val fresh = controllerFactory(endpointId)
        cachedController = fresh
        controllerEndpointId = endpointId
        return fresh
    }
}
