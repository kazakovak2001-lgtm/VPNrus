package net.pocvpn.client.debug.b45a

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.File
import net.pocvpn.client.BuildConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect

private const val TAG = "B45ASpikeVpnService"
private const val SPIKE_SESSION_NAME = "B45A Spike (SPIKE ONLY - not a real VPN)"
private const val PROTECT_STATUS_POLL_INTERVAL_MILLIS = 300L
private const val SPIKE_WORKING_DIR_NAME = "b45a-spike"

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Debug-build-only [VpnService] that proves ONLY the Android-side mechanics
 * needed for a future independent shadowsocks-rust transport (TUN
 * establish + fd handoff + outbound-socket protect + deterministic
 * lifecycle) - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md. Present only in the
 * `debug` Gradle source set (this file, its manifest entry in
 * `src/debug/AndroidManifest.xml`, and the pinned `sslocal` binary shipped
 * as a plain debug-only ASSET under `src/debug/assets/b45a/`) - genuinely
 * absent from a release build, the same discipline
 * [net.pocvpn.client.debug.XrayDiagnosticsActivity] already established
 * (B8K1B).
 *
 * **Binary packaging - two corrections, both physical-test-driven (see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 22-26):**
 *
 * 1. An early version resolved the binary via `applicationInfo.nativeLibraryDir`,
 *    assuming Gradle's `jniLibs` packaging would extract it to a real
 *    filesystem path. A physical smoke test (Section 22) found this
 *    project's merged manifest declared `extractNativeLibs="false"` (the
 *    modern AGP default) - `nativeLibraryDir` was confirmed genuinely empty.
 *    Section 23's fix moved the binary to a plain debug-only ASSET,
 *    extracted to `filesDir` and `chmod`'d at runtime instead.
 * 2. That asset/`filesDir` design was itself then physically rejected
 *    (Section 24.2): the real app process's own `ProcessBuilder.exec()` of
 *    a file the app wrote to its own private storage was denied by the OS
 *    (`error=13, Permission denied`, corroborated by an OEM
 *    kernel-security-module log naming the exact path/UID) - a W^X-class
 *    restriction. A `run-as`-based pre-implementation probe had wrongly
 *    predicted this would work; `run-as` does not replicate the real
 *    Zygote-forked app process's exact SELinux domain (Section 24.2's own
 *    "standing lesson").
 *
 * **Current, third design (Section 26 packaging-route decision pass) -
 * back to `nativeLibraryDir`, this time genuinely extracted:** AGP 8.7.3's
 * public, non-internal Variant API exposes
 * `ApplicationVariant.packaging.jniLibs.useLegacyPackaging` (a
 * `Property<Boolean>`, distinct from the DSL-only, whole-module property
 * Section 23.1 originally found), settable per-variant via
 * `androidComponents.onVariants(selector().withName("debug")) { ... }` in
 * `android/app/build.gradle.kts` - applied ONLY to the `debug` variant,
 * proven not to change `release`'s own packaging (byte-identical release
 * APK SHA-256, `packageRelease` stayed `UP-TO-DATE`). This makes the
 * Android package manager itself extract
 * `src/debug/jniLibs/arm64-v8a/libsslocal_spike.so` to
 * `applicationInfo.nativeLibraryDir` at install time, with SELinux label
 * `u:object_r:apk_data_file:s0` - a different, OS-trusted label than the
 * `filesDir` entry design 2 above used - and a real on-device probe
 * confirmed the real app process can now `exec()` it
 * (`exit=0 output="shadowsocks 1.25.0"`, Section 26.5). [B45ANativeBinaryResolver]
 * is the one place this path is resolved - it never copies, chmods, or
 * relabels the file, since the package manager already owns its
 * permissions/label; it only validates what is already there.
 *
 * Configuration is deliberately minimal and NEVER clones production routing
 * policy (Phase 4's own requirement): a narrow, non-default test subnet
 * route only (`10.202.45.0/24`), no DNS server configured, no default
 * `0.0.0.0/0` route - so even an accidental start cannot hijack the
 * device's real internet traffic. This proves fd handoff/protect mechanics
 * only; it is not meant to, and does not, carry real application traffic in
 * this phase (Q5 of the B45A acceptance matrix stays BLOCKED regardless of
 * what this class does).
 *
 * Only ONE [B45ARuntime] instance exists per process, held here - this
 * class is the ONLY [VpnService] owner and the ONLY thing that establishes
 * or closes the TUN [ParcelFileDescriptor], matching the "one VpnService
 * owner" pattern [net.pocvpn.client.vpn.xray.NovaXrayVpnService] already
 * uses for production transports (never a second connection authority,
 * architecture principle 11).
 *
 * **Lifecycle-state correction (physical-test-driven):** [handleStop] is
 * now the SOLE, unconditional authority for the SERVICE-level [_status] -
 * it always ends in [B45ARuntimePhase.STOPPED], regardless of whether a
 * [B45ARuntime] was ever created (a prior version relied entirely on
 * forwarding `runtime.status`, which never fired when [handleStart] failed
 * before constructing one - e.g. [B45ASpikeError.BinaryMissing] - leaving
 * the UI stuck showing a stale FAILED status even after a real, successful
 * Stop). [statusCollectionJob] is explicitly cancelled before the terminal
 * state is written, so a late in-flight emission from an old runtime's
 * `status` flow can never clobber it back to a stale value.
 */
class B45ASpikeVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var runtime: B45ARuntime? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var statusCollectionJob: Job? = null
    private var protectStatusPollJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> handleStart()
            ACTION_STOP -> handleStop()
            else -> Log.w(TAG, "onStartCommand: unrecognized action ${intent?.action}")
        }
        return START_NOT_STICKY
    }

    private fun handleStart() {
        if (runtime?.status?.value?.phase == B45ARuntimePhase.RUNNING) {
            Log.w(TAG, "B45A spike already running - ignoring duplicate start")
            return
        }

        val resolution = B45ANativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir)
        val binaryPath = when (resolution) {
            is B45ANativeBinaryResolver.Result.Found -> resolution.file
            is B45ANativeBinaryResolver.Result.Missing -> {
                _status.value = B45ASpikeStatus(
                    phase = B45ARuntimePhase.FAILED,
                    lastError = B45ASpikeError.BinaryMissing(resolution.reason),
                )
                Log.e(TAG, "spike binary resolution failed: ${resolution.reason}")
                return
            }
        }

        val builder = Builder()
            .addAddress(B45ATunNetworkConfig.ADDRESS, B45ATunNetworkConfig.PREFIX_LENGTH)
            .addRoute(B45ATunNetworkConfig.ROUTE, B45ATunNetworkConfig.PREFIX_LENGTH)
            .setMtu(B45ATunNetworkConfig.MTU)
            .setSession(SPIKE_SESSION_NAME)
            .setBlocking(false)
        // Round 6 (data-plane validation) - only when a real, non-fallback
        // data-plane target is configured (see B45ATunNetworkConfig's own
        // doc comment) does real application traffic need to reach the
        // TUN at all; every mechanics-only checkout keeps the original
        // narrow-route-only safety property unchanged.
        if (BuildConfig.B45A_TEST_SERVER_HOST.isNotBlank()) {
            builder.addRoute(B45ATunNetworkConfig.DEFAULT_ROUTE, B45ATunNetworkConfig.DEFAULT_ROUTE_PREFIX)
        }
        val established = builder.establish()

        if (established == null) {
            _status.value = B45ASpikeStatus(
                phase = B45ARuntimePhase.FAILED,
                lastError = B45ASpikeError.SpawnFailed("VpnService.Builder.establish() returned null - VPN permission not granted?"),
            )
            return
        }
        tunFd = established

        val workingDir = File(filesDir, SPIKE_WORKING_DIR_NAME)

        val newRuntime = B45ARuntime(
            launcher = RealB45AProcessLauncher(),
            tunFdBridge = RealB45ATunFdBridge(),
            protectBridge = RealB45AVpnProtectBridge(),
            protector = B45AVpnProtector { fd -> protect(fd) },
            scope = serviceScope,
        )
        runtime = newRuntime

        statusCollectionJob = serviceScope.launch collector@{
            newRuntime.status.collect { status ->
                _status.value = status
                // Phase 9 (Section 26): a startup failure at ANY point after
                // TUN establish (protect-listener bind, spawn, TUN-fd
                // handoff timeout, or an unexpected process exit) must not
                // leave the VPN status-bar icon lit for an interface that is
                // carrying no traffic. This is a deliberate behavior change
                // from the earlier "only explicit Stop closes the TUN fd"
                // policy - that policy remains correct for the SUCCESSFUL
                // running case (never auto-torn-down from a background
                // thread), but a FAILED status is not "successfully
                // running": every FAILED-producing path here has already
                // stopped the process/protect bridge itself (B45ARuntime's
                // own start()/onProcessExitedUnexpectedly()) - only the
                // Android-owned TUN fd and this service's own runtime/job
                // references were still outstanding.
                if (status.phase == B45ARuntimePhase.FAILED) {
                    runtime = null
                    runCatching { tunFd?.close() }
                    tunFd = null
                    statusCollectionJob = null
                    protectStatusPollJob?.cancel()
                    protectStatusPollJob = null
                    // Cancel this collector's own launch{} coroutine (not
                    // the FlowCollector receiver) - `newRuntime.status` is a
                    // StateFlow that will never emit past this terminal
                    // FAILED value, so without this the coroutine would
                    // otherwise suspend forever waiting on a value that
                    // never arrives (a leak across repeated failed starts).
                    this@collector.cancel()
                }
            }
        }

        val started = newRuntime.start(
            binaryPath.absolutePath,
            established.fd,
            workingDir,
            tunInterfaceAddressCidr = B45ATunNetworkConfig.CIDR,
        )
        if (!started) {
            Log.w(TAG, "B45ARuntime.start() refused (already running, or immediate failure - see status)")
            return
        }

        // Round 6 (data-plane validation) - periodically pulls the protect
        // bridge's real state/request/failure counters into the UI-visible
        // status (see B45ARuntime.refreshProtectStatus's own doc comment
        // for why this lives here, Android-service-only, rather than as an
        // unconditional background loop inside the unit-tested B45ARuntime
        // itself). `isActive`-bound, not "while RUNNING" - so it always
        // actually terminates when cancelled below, rather than relying on
        // a status value it might race with.
        protectStatusPollJob = serviceScope.launch {
            while (isActive) {
                newRuntime.refreshProtectStatus()
                delay(PROTECT_STATUS_POLL_INTERVAL_MILLIS)
            }
        }
    }

    private fun handleStop() {
        // Cancel first: an old runtime's `status` flow could otherwise emit
        // one more (stale) value after we write the terminal STOPPED state
        // below, clobbering it back. This is the fix for the physical-test
        // defect where Stop-after-a-failed-Start left the UI stuck FAILED.
        statusCollectionJob?.cancel()
        statusCollectionJob = null
        protectStatusPollJob?.cancel()
        protectStatusPollJob = null

        // Real cleanup, if there is anything to clean - never attempts a
        // process kill when nothing was ever spawned (B45ARuntime.stop()'s
        // own canStop()/isAlive() checks already guarantee this).
        runtime?.stop()
        runtime = null

        // The ParcelFileDescriptor is the SOLE owner of the underlying TUN fd
        // in this process - closing it exactly once, here, is what actually
        // tears down the interface. sslocal's own duplicate (received via
        // SCM_RIGHTS) is independent and closed by sslocal's own process
        // exit, which B45ARuntime.stop() already waited for above.
        runCatching { tunFd?.close() }
        tunFd = null

        // Stop is terminal cleanup AND state normalization - unconditionally
        // ends STOPPED, whether or not a runtime/TUN/process ever existed
        // (STOPPED -> Stop -> STOPPED, FAILED -> Stop -> STOPPED, RUNNING ->
        // Stop -> STOPPED all converge here identically). lastError from a
        // prior failed attempt is intentionally NOT preserved past this
        // point - the runtime lifecycle state is authoritative STOPPED; a
        // diagnostic trail of the prior error remains in logcat.
        _status.value = B45ASpikeStatus.IDLE

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
        const val ACTION_START = "net.pocvpn.client.debug.b45a.START"
        const val ACTION_STOP = "net.pocvpn.client.debug.b45a.STOP"

        private val _status = MutableStateFlow(B45ASpikeStatus.IDLE)

        /** Observed by [B45ASpikeActivity] - process-wide, since only one spike instance may exist at a time. */
        val status: StateFlow<B45ASpikeStatus> = _status.asStateFlow()
    }
}
