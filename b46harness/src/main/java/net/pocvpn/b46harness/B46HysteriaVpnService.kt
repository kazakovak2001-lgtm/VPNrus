package net.pocvpn.b46harness

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val TAG = "B46HysteriaVpnService"
private const val SESSION_NAME = "B46-2P Hysteria2 Physical Validation (DEBUG/RESEARCH ONLY - not a real VPN)"
private const val WORKING_DIR_NAME = "b46-hysteria"

/**
 * B46-2P - DEBUG/RESEARCH ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * [VpnService] validating the B46-2C-selected permissive architecture
 * (`xjasonlyu/tun2socks` in-process AAR + minimal Hysteria2 SOCKS5-only
 * child, real `VpnService.protect(fd)` via SCM_RIGHTS) on a physical
 * device. Lives in its own standalone application
 * (`net.pocvpn.b46harness`, see this module's `build.gradle.kts`), never
 * installed/reachable as part of Nova's own `:app` - the same
 * never-reachable-from-production discipline
 * [net.pocvpn.client.debug.b45a.B45ASpikeVpnService]/
 * [net.pocvpn.client.debug.XrayDiagnosticsActivity] already established for
 * `:app`'s own debug source set, achieved here via module separation
 * instead (required by the AAR-coexistence finding - see this module's
 * `build.gradle.kts` header).
 *
 * **TUN ownership (load-bearing, task requirement):** this class is the
 * SOLE owner of the original [ParcelFileDescriptor] returned by
 * `Builder.establish()` and closes it LAST, after the tun2socks bridge's
 * own `Stop()` has already run. The bridge receives only a DUPLICATE raw fd
 * via `ParcelFileDescriptor.dup(...).detachFd()` - `detachFd()` makes the
 * duplicate a plain raw fd this service no longer owns/closes, matching
 * `tun2socks-bridge/bridge.go`'s own ownership contract exactly (the real
 * tun2socks engine closes that exact fd number on its own `Stop()`).
 *
 * **Full-tunnel, own-UID-included (load-bearing, task requirement):** this
 * `Builder` never calls `addDisallowedApplication(BuildConfig.APPLICATION_ID)`.
 * Nova's own ordinary sockets (including every in-app probe) are captured
 * by this TUN like any other app's traffic - the ONLY traffic excluded from
 * the tunnel is the Hysteria2 child's own outbound QUIC socket, and only
 * because its fd was explicitly protected via the real
 * `VpnService.protect(fd)` call below. Without this, the physical
 * `protect(fd)` proof would be meaningless (see the task's own "IMPORTANT"
 * section).
 */
class B46HysteriaVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var runtime: B46HysteriaRuntime? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var statusCollectionJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart(useFakeFailingProtector = false)
            ACTION_START_PROTECT_FAILURE_TEST -> handleStart(useFakeFailingProtector = true)
            ACTION_STOP -> handleStop()
            ACTION_MARK_DATA_PLANE_READY -> handleMarkDataPlaneReady()
            else -> Log.w(TAG, "onStartCommand: unrecognized action ${intent?.action}")
        }
        return START_NOT_STICKY
    }

    private fun handleStart(useFakeFailingProtector: Boolean) {
        // Real, physically-found bug (see
        // docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md): this MUST
        // check the EXISTING `runtime` (if any) before constructing a new
        // one - a freshly-constructed `B46HysteriaRuntime` always starts at
        // IDLE, so `newRuntime.canStart()` was always true regardless of
        // whether a previous session was still fully running. A stray
        // double-tap of Start silently replaced `runtime` with a new
        // instance, orphaning the first session's real child process, TUN
        // dup fd, protect socket, and config file - none of which the new
        // instance's own `stop()` could ever reach, since it never held a
        // reference to them. Mirrors
        // [net.pocvpn.client.debug.b45a.B45ASpikeVpnService.handleStart]'s
        // own "check the existing runtime, not a new one" discipline.
        val existing = runtime
        if (existing != null && !existing.canStart()) {
            Log.w(TAG, "B46-2P already running (phase=${existing.status.value.phase}) - ignoring duplicate start")
            return
        }

        val newRuntime = B46HysteriaRuntime(
            protectBridge = RealB46HysteriaVpnProtectBridge(),
            launcher = RealB46HysteriaProcessLauncher(),
            tun2Socks = RealB46Tun2SocksBridge(),
            scope = serviceScope,
        )
        runtime = newRuntime
        newRuntime.starting()

        statusCollectionJob = serviceScope.launch {
            newRuntime.status.collect { status ->
                _status.value = status
                if (status.phase == B46HysteriaSpikePhase.ERROR) {
                    Log.e(TAG, "B46-2P entered ERROR: ${status.lastError}")
                }
            }
        }

        val binaryPath = when (val resolution = B46NativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir)) {
            is B46NativeBinaryResolver.Result.Found -> resolution.file.absolutePath
            is B46NativeBinaryResolver.Result.Missing -> {
                failStartup(B46HysteriaSpikeError.BinaryMissing(resolution.reason))
                return
            }
        }

        val dataPlaneConfig = when (val resolution = B46HysteriaDataPlaneConfig.resolve()) {
            is B46HysteriaDataPlaneConfig.Result.Valid -> resolution.config
            is B46HysteriaDataPlaneConfig.Result.Invalid -> {
                failStartup(B46HysteriaSpikeError.RuntimeSpawnFailed(resolution.reason))
                return
            }
        }

        val builder = Builder()
            .addAddress(B46HysteriaTunNetworkConfig.ADDRESS, B46HysteriaTunNetworkConfig.PREFIX_LENGTH)
            .addRoute("0.0.0.0", 0)
            .setMtu(B46HysteriaTunNetworkConfig.MTU)
            .setSession(SESSION_NAME)
            .setBlocking(false)
        B46HysteriaTunNetworkConfig.dnsServers.forEach { builder.addDnsServer(it) }
        // Deliberately NO addDisallowedApplication() call - see class doc.

        val established = builder.establish()
        if (established == null) {
            failStartup(B46HysteriaSpikeError.TunEstablishFailed("Builder.establish() returned null - VPN permission not granted?"))
            return
        }
        tunFd = established
        newRuntime.tunEstablished()

        val dupFd = ParcelFileDescriptor.dup(established.fileDescriptor)
        val rawDupFd = dupFd.detachFd() // ownership transferred to the raw int - tun2socks's own Stop() closes it.

        val bridgeStarted = newRuntime.startBridge(rawDupFd, B46HysteriaTunNetworkConfig.MTU, B46HysteriaTunNetworkConfig.localSocksAddr)
        if (!bridgeStarted) {
            newRuntime.stop()
            runCatching { tunFd?.close() }
            tunFd = null
            return
        }

        val workingDir = File(filesDir, WORKING_DIR_NAME)
        val protector: B46HysteriaVpnProtector = if (useFakeFailingProtector) {
            Log.w(TAG, "B46-2P CONTROLLED PROTECT-FAILURE TEST: using a fake protector that always returns false")
            FakeAlwaysFailProtector
        } else {
            B46HysteriaVpnProtector { fd -> protect(fd) }
        }

        val started = newRuntime.startChild(binaryPath, workingDir, dataPlaneConfig, protector)
        if (!started) {
            newRuntime.stop()
            runCatching { tunFd?.close() }
            tunFd = null
        }
    }

    /**
     * The operator-driven "probes actually passed" signal - never called by
     * anything other than [B46HysteriaActivity] after a REAL probe run
     * succeeded (see [B46HysteriaRuntime.markDataPlaneReady]'s own gate,
     * which additionally refuses unless the phase is already
     * `FD_CONTROL_READY`).
     */
    private fun handleMarkDataPlaneReady() {
        runtime?.markDataPlaneReady()
    }

    private fun failStartup(error: B46HysteriaSpikeError) {
        Log.e(TAG, "B46-2P startup failed: $error")
        _status.value = B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.ERROR, lastError = error)
        statusCollectionJob?.cancel()
        statusCollectionJob = null
        this.runtime = null
    }

    private fun handleStop() {
        statusCollectionJob?.cancel()
        statusCollectionJob = null

        runtime?.stop()
        runtime = null

        // This service's ParcelFileDescriptor is the sole owner of the
        // ORIGINAL TUN fd - closed here, LAST, after the bridge's own
        // Stop() (inside runtime.stop(), above) has already run.
        runCatching { tunFd?.close() }
        tunFd = null

        _status.value = B46HysteriaSpikeStatus.STOPPED
        stopSelf()
    }

    override fun onDestroy() {
        handleStop()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        handleStop()
        super.onRevoke()
    }

    companion object {
        const val ACTION_START = "net.pocvpn.b46harness.START"
        const val ACTION_START_PROTECT_FAILURE_TEST = "net.pocvpn.b46harness.START_PROTECT_FAILURE_TEST"
        const val ACTION_STOP = "net.pocvpn.b46harness.STOP"
        const val ACTION_MARK_DATA_PLANE_READY = "net.pocvpn.b46harness.MARK_DATA_PLANE_READY"

        private val _status = MutableStateFlow(B46HysteriaSpikeStatus.IDLE)
        val status: StateFlow<B46HysteriaSpikeStatus> = _status.asStateFlow()
    }
}
