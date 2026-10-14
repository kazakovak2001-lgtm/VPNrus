package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CancellationException
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

    // The session whose core is running right now - set only when a start
    // for it returns Started, cleared by any stop or failed start, always
    // under [mutex] together with the start/stop it describes. Teardown
    // reports THIS id, never the service's latest ACTION_START id, which a
    // newer start request may already have overwritten (field race: stop of
    // N queued behind N's in-flight start, then ACTION_START N+1 arrives).
    private var runningSessionId: Long? = null

    /**
     * What [stopSession] tore down and for which session (null when nothing ran or no id was given at start).
     * [otherRunningSessionId] is set when the stop was refused because a different session is running.
     */
    data class StoppedSession(val outcome: XrayCoreStopOutcome, val sessionId: Long?, val otherRunningSessionId: Long? = null)

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
    // B33 relay follow-up (round 3) - [onRelayHealthLost] threaded straight
    // through to XrayCoreController.requestStart's own param of the same
    // name (see that function's own docs) - defaults to a no-op so every
    // pre-existing caller is byte-for-byte unaffected.
    suspend fun start(
        endpointId: EndpointId,
        kind: TransportKind,
        routingMode: RoutingMode = RoutingMode.FULL_VPN,
        confirmationContext: RemoteConfirmationContext = RemoteConfirmationContext.Direct,
        onRelayHealthLost: suspend () -> Unit = {},
        xhttpConfig: XrayVlessXhttpConfig? = null,
        sessionId: Long? = null,
        onSuperseded: suspend (supersededSessionId: Long) -> Unit = {},
        onSupersededFailed: (Throwable) -> Unit = {},
    ): XrayCoreStartOutcome = mutex.withLock {
        // 3D - a START whose session id is NEWER than the running session's (ids only grow) is a
        // new owner asking for a new session, never a duplicate of the running one: the core that
        // runs for the old session is stopped first, in the same lock hold, and the old session is
        // reported through [onSuperseded] (the service publishes Stopped(old)) BEFORE the new
        // session starts. Same, older or unknown ids keep AlreadyRunning (duplicate/stale START).
        val running = runningSessionId
        if (sessionId != null && running != null && sessionId > running) {
            val stop = cachedController?.requestStop()
            runningSessionId = null
            if (stop?.didTeardown == true) {
                // 3F - the old core may still be alive. No second core is started over it and
                // Stopped(old) is NOT reported (it was not confirmed); the caller publishes
                // Failed(new) from this outcome. 3H - only an UNCONFIRMED stop counts (a throwing
                // stopLoop() whose core then reads stopped is a real stop); the shared
                // [XrayCoreStopState] keeps later STARTs blocked and a later STOP retries.
                if (stop.unconfirmed) {
                    return@withLock XrayCoreStartOutcome.CoreStartFailed("previous session did not stop: ${stop.stopLoopFailureReason}")
                }
                // 3F - only a failing PUBLISH is tolerated here (reported through
                // [onSupersededFailed]); the core is confirmed stopped, so the new START still runs.
                // Cancellation always propagates.
                try {
                    onSuperseded(running)
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Exception) {
                    onSupersededFailed(e)
                }
            }
        }
        val controller = selectControllerLocked(endpointId)
        if (controller == null) {
            // 3H - the previous endpoint's core did not confirm its stop: no new controller.
            runningSessionId = null
            return@withLock XrayCoreStartOutcome.StopUnconfirmed("previous endpoint did not stop")
        }
        val outcome = controller.requestStart(
            kind,
            routingMode,
            confirmationContext,
            onRelayHealthLost,
            xhttpConfig,
            relayHealthStop = { relayHealthStop(sessionId, onRelayHealthLost) },
        )
        runningSessionId = when (outcome) {
            XrayCoreStartOutcome.Started -> sessionId
            // The earlier session keeps running (same endpoint) - its id stays.
            XrayCoreStartOutcome.AlreadyRunning, XrayCoreStartOutcome.StartInFlight -> runningSessionId
            // Nothing runs after a failed start (an endpoint switch has already stopped the old core).
            else -> null
        }
        outcome
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
    suspend fun stop(): XrayCoreStopOutcome = stopSession().outcome

    /**
     * [stop] plus the id of the session whose core was actually torn down.
     * With [expectedSessionId] (an ACTION_STOP for that session) nothing is
     * torn down while a DIFFERENT known session is running: a late stop of
     * session N must never end session N+1.
     */
    suspend fun stopSession(expectedSessionId: Long? = null): StoppedSession = mutex.withLock { stopSessionLocked(expectedSessionId) }

    /**
     * 3J - the relay-health watchdog's stop of [sessionId], under the SAME lock as every start and
     * stop: a START can neither run between this stop and its report nor be overtaken by it, and
     * the stop never reaches a different session (the [stopSession] identity check). The watchdog
     * runs on its own coroutine and nothing here waits for it, so holding the lock cannot
     * deadlock. [onRelayHealthLost] is reported (still under the lock, so before any later
     * Started) only when THIS call tore down [sessionId]'s core; an unconfirmed stop is still
     * reported as that failure, never as Stopped.
     */
    private suspend fun relayHealthStop(sessionId: Long?, onRelayHealthLost: suspend () -> Unit) = mutex.withLock {
        val stopped = stopSessionLocked(sessionId)
        if (stopped.outcome.didTeardown && stopped.sessionId == sessionId) onRelayHealthLost()
    }

    /** Caller must already hold [mutex]. */
    private fun stopSessionLocked(expectedSessionId: Long?): StoppedSession {
        val running = runningSessionId
        if (expectedSessionId != null && running != null && running != expectedSessionId) {
            return StoppedSession(XrayCoreStopOutcome(didTeardown = false), null, otherRunningSessionId = running)
        }
        val outcome = cachedController?.requestStop() ?: XrayCoreStopOutcome(didTeardown = false)
        val stopped = if (outcome.didTeardown) runningSessionId else null
        runningSessionId = null
        return StoppedSession(outcome, stopped)
    }

    /** Caller must already hold [mutex]. Null (3H) when the old endpoint's stop was not confirmed - the old controller stays cached so a later STOP can retry it. */
    private fun selectControllerLocked(endpointId: EndpointId): XrayCoreController? {
        cachedController?.let { existing ->
            if (controllerEndpointId == endpointId) return existing
            // Authoritative teardown of the OLD endpoint's controller BEFORE
            // this new one is even constructed - endpoint B can never start
            // while endpoint A's own session is still considered active by
            // this coordinator. A not-running A is a harmless no-op; an
            // UNCONFIRMED stop of A (3H) builds nothing - A may still run.
            // The call always happens, and always completes, before B's
            // controller is built, under the SAME lock.
            if (existing.requestStop().unconfirmed) return null
        }
        val fresh = controllerFactory(endpointId)
        cachedController = fresh
        controllerEndpointId = endpointId
        return fresh
    }
}
