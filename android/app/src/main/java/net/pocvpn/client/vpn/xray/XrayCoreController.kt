package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * What one [XrayCoreController.requestStart] call actually did - the caller
 * ([NovaXrayVpnService]) turns this into logging/stopSelf() decisions. Never
 * carries anything but an exception class name or [XrayRuntimeResolution]'s
 * own reason string - no secret ever appears here.
 */
sealed class XrayCoreStartOutcome {
    /** startLoop() was called and returned without throwing. */
    object Started : XrayCoreStartOutcome()

    /** A start was already running - see [XrayServiceLifecycleGate]. No Builder/core/tun touched. */
    object AlreadyRunning : XrayCoreStartOutcome()

    /** Another start is currently in flight - see [XrayServiceLifecycleGate]. No Builder/core/tun touched. */
    object StartInFlight : XrayCoreStartOutcome()

    /** [XrayRuntimeResolver] rejected the stored profile (absent/corrupt/invalid) - startLoop() never called. */
    data class Rejected(val reason: String) : XrayCoreStartOutcome()

    /** establishTun threw or returned null - startLoop() never called. */
    data class EstablishFailed(val reason: String) : XrayCoreStartOutcome()

    /** startLoop() itself threw - the just-established tun is closed before returning. */
    data class CoreStartFailed(val reason: String) : XrayCoreStartOutcome()

    /**
     * B33 - startLoop() itself returned without throwing (the LOCAL core is
     * genuinely running), but the bounded post-start remote/data-plane
     * confirmation (see [XrayCoreController.requestStart]'s own docs) never
     * proved the tunnel is actually usable - a real handshake/HTTP round
     * trip through the just-established outbound never succeeded within the
     * bound. Deliberately distinct from [CoreStartFailed] (that means the
     * LOCAL startLoop() call itself threw - a different, earlier failure)
     * - callers must never conflate "local process wouldn't even start" with
     * "local process started but the remote gateway never confirmed". The
     * loop is stopped and the tun closed before this is ever returned -
     * never left half-up.
     */
    data class RemoteUnconfirmed(val reason: String) : XrayCoreStartOutcome()
}

/** Result of one [XrayCoreController.requestStop] call. */
data class XrayCoreStopOutcome(
    /** False (no-op - matches [XrayServiceLifecycleGate.tryBeginTeardown]'s own contract) if nothing was running. */
    val didTeardown: Boolean,
    /** Non-null only if stopLoop() itself threw - the tun is still closed regardless (see [requestStop][XrayCoreController.requestStop]). */
    val stopLoopFailureReason: String? = null,
)

/**
 * B8K4C - [NovaXrayVpnService]'s actual start/stop decision and sequencing,
 * decoupled from android.app.Service/android.net.VpnService.Builder so
 * "duplicate start creates no duplicate core", "absent/corrupt/invalid
 * profile never starts Xray", "stop calls stopLoop and releases the tun fd
 * exactly once" are all unit-testable on the plain JVM against a fake
 * [XrayCoreRuntime] (this project has no Robolectric dependency). Reuses
 * [XrayServiceLifecycleGate] verbatim for the duplicate-start/duplicate-
 * teardown invariant rather than reimplementing it.
 *
 * [establishTun] returns a raw file descriptor [Int] (not a
 * android.os.ParcelFileDescriptor) so this class stays entirely free of
 * Android SDK types - [NovaXrayVpnService] owns the real
 * ParcelFileDescriptor's lifetime and hands back only its `.fd`.
 */
class XrayCoreController(
    private val repository: XrayProfileRepository,
    private val coreRuntime: XrayCoreRuntime,
    private val novaPackageId: String,
    private val ensureCoreEnvInitialized: () -> Unit,
    private val establishTun: (XrayVpnBuilderPlan) -> Int?,
    private val closeTun: () -> Unit,
    // B8O2 - additive, defaults to null so every existing call site (real or
    // test) is byte-for-byte unaffected: with no TLS repository wired,
    // requestStart(TransportKind.TLS_TCP) simply rejects (see below) rather
    // than throwing - the same fail-closed shape as a missing REALITY
    // profile, never a crash.
    private val tlsRepository: XrayTlsProfileRepository? = null,
    // B33 review fix (round 2, blocker) - a scope the bounded remote-
    // confirmation probe's BLOCKING native call runs on, deliberately NOT
    // derived from the calling coroutine (see confirmRemoteConnectivity's
    // own docs for exactly why: a coroutine timeout cannot preempt an
    // ordinary blocking JNI call with no suspension point, so the call must
    // run somewhere the timeout can walk away from without cancelling it).
    // Defaults to a real, independent, long-lived scope for production;
    // test-injectable (same "collaborator injection" pattern this class
    // already uses for [establishTun]/[closeTun]/[coreRuntime]) so a test
    // can use its own controllable scope/dispatcher instead of a real
    // background thread.
    private val probeScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
) {
    private val lifecycleGate = XrayServiceLifecycleGate()

    // B33 - [serverHost] carries the exact plaintext destination host THIS
    // attempt resolved (XrayVlessRealityConfig.server / XrayVlessTlsConfig.server -
    // never re-derived from anywhere else) so the post-start confirmation
    // probe below targets the SAME real gateway this attempt actually
    // dials, never a different/fabricated address.
    private class ReadyToStart(val plan: XrayVpnBuilderPlan, val renderedConfig: String, val serverHost: String)

    /**
     * [kind] defaults to [TransportKind.XRAY_REALITY] so every existing
     * call site (real or test) that calls `requestStart()` with no argument
     * is byte-for-byte unaffected - REALITY's own resolve/build path below
     * is untouched. [TransportKind.TLS_TCP] resolves against [tlsRepository]
     * instead (see [XrayRuntimeResolver.resolveTls]) - both share the SAME
     * [lifecycleGate]/tun/coreRuntime, so REALITY and TLS_TCP can never run
     * concurrently through this one controller instance (there is only ever
     * one active Xray session per [net.pocvpn.client.vpn.xray.NovaXrayVpnService]).
     * Any other [kind] is rejected before touching the tun/core at all -
     * structurally unreachable via the public API today (only these two
     * kinds are ever passed in), same "defensive, not a real code path"
     * shape [XrayCoreStartOutcome.Rejected]'s other call sites already use.
     */
    // B18-2 - [routingMode] defaults to FULL_VPN so every pre-B18-2 call site
    // (real or test) is byte-for-byte unaffected - see buildXrayVpnPlan's own
    // docs for the exact route-set contract this threads into.
    suspend fun requestStart(kind: TransportKind = TransportKind.XRAY_REALITY, routingMode: RoutingMode = RoutingMode.FULL_VPN): XrayCoreStartOutcome {
        when (lifecycleGate.tryBeginStart()) {
            XrayServiceStartDecision.IGNORE_ALREADY_RUNNING -> return XrayCoreStartOutcome.AlreadyRunning
            XrayServiceStartDecision.IGNORE_START_IN_FLIGHT -> return XrayCoreStartOutcome.StartInFlight
            XrayServiceStartDecision.PROCEED -> Unit
        }

        var success = false
        try {
            val ready = when (kind) {
                TransportKind.TLS_TCP -> {
                    val tlsRepo = tlsRepository
                        ?: return XrayCoreStartOutcome.Rejected("Xray TLS profile repository not wired")
                    when (val resolution = XrayRuntimeResolver.resolveTls(tlsRepo)) {
                        is XrayTlsRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                        is XrayTlsRuntimeResolution.Ready ->
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId, routingMode), resolution.renderedConfig, resolution.config.server)
                    }
                }
                TransportKind.XRAY_REALITY -> {
                    when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                        is XrayRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                        is XrayRuntimeResolution.Ready ->
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId, routingMode), resolution.renderedConfig, resolution.config.server)
                    }
                }
                else -> return XrayCoreStartOutcome.Rejected("unsupported transport kind for NovaXrayVpnService: $kind")
            }

            val plan = ready.plan
            val fd = try {
                establishTun(plan)
            } catch (t: Throwable) {
                return XrayCoreStartOutcome.EstablishFailed(t.javaClass.simpleName)
            } ?: return XrayCoreStartOutcome.EstablishFailed("establish() returned null")

            return try {
                ensureCoreEnvInitialized()
                coreRuntime.startLoop(ready.renderedConfig, fd)
                // B33 - startLoop() returning without throwing proves ONLY
                // that the LOCAL core/tun exist - see confirmRemoteConnectivity's
                // own docs for why that is never, by itself, sufficient
                // evidence the tunnel is actually usable.
                if (confirmRemoteConnectivity(ready.serverHost)) {
                    success = true
                    XrayCoreStartOutcome.Started
                } else {
                    // B33 - the local loop IS running (startLoop() did not
                    // throw) but was never confirmed usable within the
                    // bound - stop it and release the tun ourselves (never
                    // left half-up): lifecycleGate.endStart(false) below
                    // means tryBeginTeardown() will never fire for this
                    // attempt (isRunning was never set true), so this is the
                    // ONLY teardown this attempt will ever get.
                    val stopReason = try {
                        coreRuntime.stopLoop()
                        null
                    } catch (t: Throwable) {
                        t.javaClass.simpleName
                    }
                    closeTun()
                    XrayCoreStartOutcome.RemoteUnconfirmed(stopReason?.let { "remote handshake not confirmed (stopLoop also failed: $it)" } ?: "remote handshake not confirmed")
                }
            } catch (t: Throwable) {
                closeTun()
                XrayCoreStartOutcome.CoreStartFailed(t.javaClass.simpleName)
            }
        } finally {
            lifecycleGate.endStart(success)
        }
    }

    /**
     * B33 - the ONE real, positive, production-capable confirmation that the
     * just-started Xray tunnel is genuinely usable beyond local process
     * startup: a bounded [XrayCoreRuntime.measureDelay] round trip through
     * the JUST-STARTED core's own configured outbound/routing (the exact
     * same real native primitive v2rayNG's own "test configuration" feature
     * uses - see [XrayCoreRuntime.measureDelay]'s own docs), targeting THIS
     * attempt's own real gateway's already-deployed, unauthenticated
     * `/v1/manifest` endpoint on port 443 (a real Let's Encrypt IP-SAN
     * certificate is deployed on both production gateways - verified
     * directly against both live hosts without `-k`/any certificate bypass,
     * `SSL certificate verify ok` in both cases - so this dials cleanly by
     * IP with full TLS verification, never a bypass) - never a third-party
     * public-IP service (task's own explicit prohibition), never a
     * fabricated/local check ("process alive"/"tun exists"), never a fixed
     * sleep.
     *
     * B33 review fix (round 2, blocker) - [XrayCoreRuntime.measureDelay] is
     * an ORDINARY BLOCKING native/JNI call with no suspension point: a
     * coroutine timeout cannot preempt it once it has started (cancellation
     * only takes effect at a suspension point, and a raw blocking call never
     * suspends) - wrapping the blocking call directly in
     * [withTimeoutOrNull] (an earlier, WRONG version of this function) does
     * NOT bound it at all, since the very coroutine running that
     * `withTimeoutOrNull` block is the SAME thread stuck inside the blocking
     * call - there is no separate execution path left for the timeout to
     * even fire on. Fixed by giving the blocking call its OWN, independent
     * coroutine on [probeScope] (deliberately NOT a structured child of THIS
     * function's own coroutine - see that field's own docs) and having
     * [withTimeoutOrNull] bound only the SUSPENDING `deferred.await()` call,
     * which genuinely can be abandoned. This makes the caller-visible
     * deadline real: [requestStart] always receives an answer within
     * [REMOTE_CONFIRM_TIMEOUT_MS], regardless of how long the underlying
     * native call actually takes.
     *
     * Safety of the abandoned call after a timeout (task's own explicit
     * requirements):
     * - **Late success/failure is inert.** [deferred] is a fresh, local
     *   object created new by EVERY call - never shared/instance-level
     *   state - so a late completion after [withTimeoutOrNull] already gave
     *   up has nothing left reading it; `complete()` on an
     *   already-abandoned (but not yet completed) deferred is harmless, and
     *   nothing in this class ever inspects a [CompletableDeferred] after
     *   its owning [confirmRemoteConnectivity] call has returned.
     * - **Never publishes Started after timeout.** [requestStart] only
     *   proceeds past this function once it has ALREADY returned (Boolean,
     *   not a background promise) - a timeout returns `false` HERE, so
     *   [requestStart] takes the [XrayCoreStartOutcome.RemoteUnconfirmed]
     *   branch synchronously, before the abandoned native call could ever
     *   complete.
     * - **Never mutates a newer attempt.** Because [deferred] is
     *   call-local (never a field on this class), a SUBSEQUENT
     *   [requestStart]/[confirmRemoteConnectivity] call - whether a retry of
     *   the same candidate or a genuinely different one - gets its OWN
     *   fresh [deferred] and its own fresh probe coroutine; there is no
     *   shared mutable state through which one attempt's abandoned probe
     *   could reach into another's outcome, by construction.
     * - **Teardown stays deterministic.** [requestStart]'s
     *   `RemoteUnconfirmed` branch calls `coreRuntime.stopLoop()`/[closeTun]
     *   synchronously the instant this function returns `false` - bounded by
     *   the SAME [REMOTE_CONFIRM_TIMEOUT_MS] deadline, never waiting on the
     *   abandoned probe.
     * - **Bounded resource growth.** Each timed-out probe leaves at most one
     *   coroutine running on [probeScope] (backed by [Dispatchers.IO]'s own
     *   bounded elastic thread pool) until the underlying native call
     *   itself eventually returns/throws (its own OS-level socket-timeout
     *   bound, outside this class's control - the pinned AAR exposes no
     *   configurable timeout parameter for `measureDelay`, confirmed against
     *   its decompiled native method signature) - at that point the
     *   coroutine completes and is automatically removed from [probeScope]'s
     *   own job bookkeeping. Never literally unbounded: the number of
     *   concurrently abandoned probes for one connect() sequence is capped
     *   by the SAME [net.pocvpn.client.smartconnect.AutoGatewaySelector.MAX_ATTEMPTS]
     *   bound that already caps the whole combined attempt sequence - this
     *   introduces no new unbounded-retry surface.
     */
    private suspend fun confirmRemoteConnectivity(serverHost: String): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        probeScope.launch {
            val confirmed = try {
                coreRuntime.measureDelay("https://$serverHost/v1/manifest")
                true
            } catch (t: Throwable) {
                false
            }
            deferred.complete(confirmed)
        }
        return withTimeoutOrNull(REMOTE_CONFIRM_TIMEOUT_MS) { deferred.await() } ?: false
    }

    private companion object {
        /**
         * B33 - bounded independently of VpnController's own
         * HANDSHAKE_TIMEOUT_MS (AWG's cheap local-stats poll budget - a
         * different signal with a different cost shape, see that constant's
         * own docs): a real network round trip needs its own, longer-tail-
         * tolerant bound, but still bounded, never unbounded. This IS the
         * real caller-visible deadline (see confirmRemoteConnectivity's own
         * round-2 docs for why the ORIGINAL version of this bound was not
         * actually enforced).
         */
        const val REMOTE_CONFIRM_TIMEOUT_MS = 6_000L
    }

    fun requestStop(): XrayCoreStopOutcome {
        if (!lifecycleGate.tryBeginTeardown()) return XrayCoreStopOutcome(didTeardown = false)
        val failureReason = try {
            coreRuntime.stopLoop()
            null
        } catch (t: Throwable) {
            t.javaClass.simpleName
        } finally {
            closeTun()
        }
        return XrayCoreStopOutcome(didTeardown = true, stopLoopFailureReason = failureReason)
    }
}
