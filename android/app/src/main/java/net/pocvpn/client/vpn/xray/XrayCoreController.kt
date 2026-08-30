package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.transport.TransportKind

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
) {
    private val lifecycleGate = XrayServiceLifecycleGate()

    private class ReadyToStart(val plan: XrayVpnBuilderPlan, val renderedConfig: String)

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
    suspend fun requestStart(kind: TransportKind = TransportKind.XRAY_REALITY): XrayCoreStartOutcome {
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
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId), resolution.renderedConfig)
                    }
                }
                TransportKind.XRAY_REALITY -> {
                    when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                        is XrayRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                        is XrayRuntimeResolution.Ready ->
                            ReadyToStart(buildXrayVpnPlan(resolution.config, novaPackageId), resolution.renderedConfig)
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
                success = true
                XrayCoreStartOutcome.Started
            } catch (t: Throwable) {
                closeTun()
                XrayCoreStartOutcome.CoreStartFailed(t.javaClass.simpleName)
            }
        } finally {
            lifecycleGate.endStart(success)
        }
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
