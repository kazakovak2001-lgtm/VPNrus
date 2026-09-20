package net.pocvpn.b46harness

import android.util.Log
import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "B46HysteriaRuntime"
private const val PROTECT_SOCKET_FILENAME = "b46-protect.sock"
private const val CONFIG_FILENAME = "b46-hysteria-config.json"
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L
private const val DEFAULT_BRIDGE_STOP_TIMEOUT_MILLIS = 2_000L

/**
 * B46-2P - DEBUG/RESEARCH ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * The single owner of the tun2socks bridge, the [B46HysteriaVpnProtectBridge]
 * listener, and the Hysteria2 child process - mirrors
 * [net.pocvpn.client.debug.b45a.B45ARuntime]'s own "one class touches all
 * three, so shutdown ordering lives in exactly one place" discipline.
 * [B46HysteriaVpnService] is the ONLY caller; this class never touches
 * `VpnService`/TUN-fd-establish itself (it receives an already-duplicated
 * raw fd, see the ownership contract in
 * `research/b46-2p-android-physical/tun2socks-bridge/bridge.go`).
 *
 * Never wired into TransportRegistry/SmartConnectDecisionEngine/
 * AutoGatewaySelector/TransportOrchestrator/production VpnController/
 * MainViewModel - reachable ONLY from [B46HysteriaVpnService], itself
 * reachable ONLY from the debug-only `B46HysteriaActivity`.
 */
internal class B46HysteriaRuntime(
    private val protectBridge: B46HysteriaVpnProtectBridge,
    private val launcher: B46HysteriaProcessLauncher,
    private val tun2Socks: B46Tun2SocksBridge,
    private val scope: CoroutineScope,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val forceStopWaitMillis: Long = DEFAULT_FORCE_STOP_WAIT_MILLIS,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val _status = MutableStateFlow(B46HysteriaSpikeStatus.IDLE)
    val status: StateFlow<B46HysteriaSpikeStatus> = _status.asStateFlow()

    private var process: B46HysteriaSpawnedProcess? = null
    private var workingDir: File? = null
    private var configFile: File? = null
    private var protectSocketFile: File? = null

    fun canStart(): Boolean = B46HysteriaSpikeTransitions.canStart(_status.value)

    fun starting() {
        _status.value = B46HysteriaSpikeTransitions.starting()
    }

    fun tunEstablished() {
        _status.value = B46HysteriaSpikeTransitions.tunEstablished(_status.value)
    }

    /**
     * [dupFd] MUST already be a duplicate of the VpnService's TUN fd - see
     * the ownership contract in `tun2socks-bridge/bridge.go`. This class
     * never dups or closes the original TUN fd itself.
     */
    fun startBridge(dupFd: Int, mtu: Int, socksAddr: String): Boolean {
        val result = tun2Socks.start(dupFd, mtu, socksAddr)
        return when (result) {
            is B46Tun2SocksResult.Ok -> {
                _status.value = B46HysteriaSpikeTransitions.tunBridgeReady(_status.value)
                true
            }
            is B46Tun2SocksResult.Failed -> {
                Log.e(TAG, "tun2socks bridge start failed: ${result.reason}")
                _status.value = B46HysteriaSpikeTransitions.failed(_status.value, B46HysteriaSpikeError.BridgeStartFailed(result.reason))
                false
            }
        }
    }

    /**
     * Writes the config file (mode 600, deleted on stop), starts the real
     * protect bridge, and spawns the Hysteria2 child with ONLY
     * `--config-file` (never `--auth`, per the task's secret-handling
     * requirement). [protector] is the real `VpnService.protect(fd)`
     * closure from [B46HysteriaVpnService] - or [FakeAlwaysFailProtector]
     * for the controlled protect-failure test cycle ONLY.
     */
    fun startChild(binaryPath: String, workingDir: File, config: B46HysteriaChildConfig, protector: B46HysteriaVpnProtector): Boolean {
        workingDir.mkdirs()
        this.workingDir = workingDir

        if (!File(binaryPath).exists()) {
            _status.value = B46HysteriaSpikeTransitions.failed(_status.value, B46HysteriaSpikeError.BinaryMissing(binaryPath))
            return false
        }

        val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
        protectSocketFile = protectSocketPath
        val configPath = File(workingDir, CONFIG_FILENAME)
        configFile = configPath

        try {
            protectBridge.start(protectSocketPath, decorateProtector(protector))
        } catch (t: Throwable) {
            _status.value = B46HysteriaSpikeTransitions.failed(_status.value, B46HysteriaSpikeError.FdControlHandoffFailed(t.message ?: "protect bridge bind failed"))
            return false
        }

        val configWithProtectPath = config.copy(protectPath = protectSocketPath.absolutePath)
        try {
            writeChildConfigFile(configPath, configWithProtectPath)
        } catch (t: Throwable) {
            protectBridge.stop()
            _status.value = B46HysteriaSpikeTransitions.failed(_status.value, B46HysteriaSpikeError.RuntimeSpawnFailed("config file write failed: ${t.message}"))
            return false
        }
        Log.i(TAG, "config-file written: ${configWithProtectPath.redactedSummary()}")

        val args = listOf("--config-file", configPath.absolutePath)
        val spawned = try {
            launcher.launch(binaryPath, args, workingDir)
        } catch (t: Throwable) {
            protectBridge.stop()
            _status.value = B46HysteriaSpikeTransitions.failed(_status.value, B46HysteriaSpikeError.RuntimeSpawnFailed(t.message ?: "unknown"))
            return false
        }
        process = spawned
        spawned.onExit { exitCode -> onProcessExitedUnexpectedly(exitCode) }
        spawned.onLogLine { line -> onChildLogLine(line) }

        _status.value = B46HysteriaSpikeTransitions.runtimeStarted(_status.value, spawned.pid ?: -1)
        return true
    }

    /** Wraps the real protector so every request/success/failure is recorded and FD_CONTROL_READY fires on the first success. */
    private fun decorateProtector(real: B46HysteriaVpnProtector): B46HysteriaVpnProtector = B46HysteriaVpnProtector { fd ->
        val succeeded = real.protect(fd)
        _status.value = B46HysteriaSpikeTransitions.onFdControlRequestHandled(_status.value, succeeded)
        if (succeeded && _status.value.phase == B46HysteriaSpikePhase.RUNTIME_STARTED) {
            _status.value = B46HysteriaSpikeTransitions.fdControlReady(_status.value)
        }
        succeeded
    }

    private fun onChildLogLine(line: String) {
        // Real, physically-found bug: NOT `startsWith` - the child's own
        // Go `log` package prefixes every line with a timestamp
        // ("2026/09/20 05:31:03 connected: ..."), so `startsWith` never
        // matched and these fields silently stayed false despite the real
        // events having genuinely happened (see
        // docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md).
        when {
            line.contains("connected: udpEnabled") ->
                _status.value = B46HysteriaSpikeTransitions.withChildLogObservation(_status.value, quicHandshakeConnected = true)
            line.contains("SOCKS5_LISTENING") ->
                _status.value = B46HysteriaSpikeTransitions.withChildLogObservation(_status.value, socksListenerReady = true)
        }
    }

    /**
     * Only reachable after [B46HysteriaSpikePhase.FD_CONTROL_READY] AND a
     * real proxied-traffic probe succeeded - callers (the debug Activity's
     * probe runner) must never call this from mere process/protect-success
     * alone. See [B46HysteriaSpikeTransitions.dataPlaneReady]'s own gate.
     */
    fun markDataPlaneReady() {
        _status.value = B46HysteriaSpikeTransitions.dataPlaneReady(_status.value)
    }

    fun canStop(): Boolean = B46HysteriaSpikeTransitions.canStop(_status.value)

    /** Idempotent. Ordering: STOPPING -> stop bridge -> child graceful/force stop -> stop protect bridge -> delete config/socket -> STOPPED. */
    fun stop() {
        val current = _status.value
        if (!B46HysteriaSpikeTransitions.canStop(current)) return
        _status.value = B46HysteriaSpikeTransitions.stopping(current)

        val bridgeStopResult = tun2Socks.stop()
        if (bridgeStopResult is B46Tun2SocksResult.Failed) {
            Log.w(TAG, "tun2socks StopBridge reported: ${bridgeStopResult.reason}")
        }

        val proc = process
        if (proc != null && proc.isAlive()) {
            proc.requestStop()
            val exited = proc.waitForExit(gracefulStopTimeoutMillis)
            if (exited == null) {
                proc.forceStop()
                proc.waitForExit(forceStopWaitMillis)
            }
        }

        protectBridge.stop()
        configFile?.delete()
        protectSocketFile?.delete()

        process = null
        workingDir = null
        configFile = null
        protectSocketFile = null
        _status.value = B46HysteriaSpikeTransitions.stopped()
    }

    private fun onProcessExitedUnexpectedly(exitCode: Int) {
        val phase = _status.value.phase
        if (phase != B46HysteriaSpikePhase.STOPPING && phase != B46HysteriaSpikePhase.STOPPED) {
            protectBridge.stop()
            process = null
            _status.value = B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly(_status.value, exitCode)
        }
    }
}
