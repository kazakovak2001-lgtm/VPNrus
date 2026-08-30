package net.pocvpn.client.vpn.xray

import net.pocvpn.client.identity.XrayProfileRepository

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
) {
    private val lifecycleGate = XrayServiceLifecycleGate()

    suspend fun requestStart(): XrayCoreStartOutcome {
        when (lifecycleGate.tryBeginStart()) {
            XrayServiceStartDecision.IGNORE_ALREADY_RUNNING -> return XrayCoreStartOutcome.AlreadyRunning
            XrayServiceStartDecision.IGNORE_START_IN_FLIGHT -> return XrayCoreStartOutcome.StartInFlight
            XrayServiceStartDecision.PROCEED -> Unit
        }

        var success = false
        try {
            val ready = when (val resolution = XrayRuntimeResolver.resolve(repository)) {
                is XrayRuntimeResolution.Rejected -> return XrayCoreStartOutcome.Rejected(resolution.reason)
                is XrayRuntimeResolution.Ready -> resolution
            }

            val plan = buildXrayVpnPlan(ready.config, novaPackageId)
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
