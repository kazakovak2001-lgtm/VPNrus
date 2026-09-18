package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

private const val PROTECT_SOCKET_FILENAME = "protect_path"
private const val TUN_FD_SOCKET_FILENAME = "tun_fd_path"
private const val RUNTIME_CONFIG_FILENAME = "runtime_config.json"
private const val DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS = 5_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/** Everything needed to start one sslocal session - never held longer than one [ShadowsocksRuntime.start] call; the key never appears in [toString]. */
internal data class ShadowsocksRuntimeTarget(
    val host: String,
    val port: Int,
    val method: String,
    val keyBase64: String,
) {
    override fun toString(): String = "ShadowsocksRuntimeTarget(host=$host, port=$port, method=$method, key=<redacted>)"
}

/**
 * B45B-3 - production runtime, the isolated-adapter-shell counterpart of the
 * debug-only B45ARuntime it is adapted from (never sharing state or
 * lifecycle with it). Owns the pinned sslocal process, the protect listener,
 * the TUN-fd handoff, and the plaintext runtime config file's full lifetime -
 * the one class that touches all four, so ownership/shutdown ordering lives
 * in exactly one place.
 *
 * This is not, and must never become, a second production connection
 * authority: it is reachable only from [ShadowsocksTransport]/
 * [ShadowsocksVpnService], and SHADOWSOCKS_2022 stays NOT_IMPLEMENTED in
 * TransportRegistry - see this slice's own instructions.
 */
internal class ShadowsocksRuntime(
    private val launcher: ShadowsocksProcessLauncher,
    private val tunFdBridge: ShadowsocksTunFdBridge,
    private val protectBridge: ShadowsocksVpnProtectBridge,
    private val protector: ShadowsocksVpnProtector,
    private val scope: CoroutineScope,
    private val tunFdHandoffTimeoutMillis: Long = DEFAULT_TUN_FD_HANDOFF_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val _status = MutableStateFlow(ShadowsocksRuntimeStatus.IDLE)
    val status: StateFlow<ShadowsocksRuntimeStatus> = _status.asStateFlow()

    private var process: ShadowsocksSpawnedProcess? = null
    private var runtimeConfigFile: File? = null

    /**
     * [binaryPath] must already exist ([ShadowsocksNativeBinaryResolver]).
     * [tunFd] is the raw fd of an already-established VpnService.Builder
     * result - this class never establishes the TUN itself (that stays
     * [ShadowsocksVpnService]'s job). [target] carries the decrypted
     * credential for exactly this call - the caller never retains it beyond
     * calling this. Returns false immediately if already
     * STARTING/RUNNING/STOPPING (never a double-start).
     */
    fun start(
        binaryPath: String,
        tunFd: Int,
        workingDir: File,
        tunInterfaceAddressCidr: String,
        target: ShadowsocksRuntimeTarget,
    ): Boolean {
        val current = _status.value
        if (current.phase == ShadowsocksRuntimePhase.STARTING ||
            current.phase == ShadowsocksRuntimePhase.RUNNING ||
            current.phase == ShadowsocksRuntimePhase.STOPPING
        ) {
            return false
        }
        _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.STARTING)

        if (!File(binaryPath).exists()) {
            fail(ShadowsocksRuntimeError.BinaryMissing("binary not found at $binaryPath"))
            return false
        }

        workingDir.mkdirs()
        val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
        val tunSocketPath = File(workingDir, TUN_FD_SOCKET_FILENAME)

        val configFile = try {
            ShadowsocksRuntimeConfigWriter.write(
                directory = workingDir,
                fileName = RUNTIME_CONFIG_FILENAME,
                host = target.host,
                port = target.port,
                method = target.method,
                keyBase64 = target.keyBase64,
            )
        } catch (t: Throwable) {
            fail(ShadowsocksRuntimeError.RuntimeConfigWriteFailed(t.javaClass.simpleName))
            return false
        }
        runtimeConfigFile = configFile

        // Protect listener MUST bind before sslocal starts - sslocal connects fresh per outbound socket, and a not-yet-bound path would simply fail to connect.
        try {
            protectBridge.start(protectSocketPath, protector)
        } catch (t: Throwable) {
            ShadowsocksRuntimeConfigWriter.delete(configFile)
            runtimeConfigFile = null
            fail(ShadowsocksRuntimeError.ProtectListenerFailed(t.message ?: "unknown"))
            return false
        }

        // Never argv - only the config-file path and non-secret flags (Phase 7/8).
        val args = listOf(
            "-c", configFile.absolutePath,
            "--protocol", "tun",
            "--tun-device-fd-from-path", tunSocketPath.absolutePath,
            "--tun-interface-address", tunInterfaceAddressCidr,
            "--vpn",
            "-U",
        )

        val spawned = try {
            launcher.launch(binaryPath, args, workingDir)
        } catch (t: Throwable) {
            protectBridge.stop()
            ShadowsocksRuntimeConfigWriter.delete(configFile)
            runtimeConfigFile = null
            fail(ShadowsocksRuntimeError.SpawnFailed(t.message ?: "unknown"))
            return false
        }
        process = spawned
        spawned.onExit { exitCode -> onProcessExitedUnexpectedly(exitCode) }

        scope.launch(ioDispatcher) {
            val bridgeState = tunFdBridge.handOff(tunFd, tunSocketPath, tunFdHandoffTimeoutMillis)
            if (_status.value.phase != ShadowsocksRuntimePhase.STARTING) return@launch
            when (bridgeState) {
                ShadowsocksTunFdBridgeState.FD_SENT -> {
                    // Startup confirmed (Phase 7): sslocal already read the
                    // config exactly once at process start (before it could
                    // ever reach the tun-fd-handoff accept() this succeeded
                    // against) - safe to delete the plaintext secret now,
                    // strictly before RUNNING is published.
                    runtimeConfigFile?.let { ShadowsocksRuntimeConfigWriter.delete(it) }
                    runtimeConfigFile = null
                    _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.RUNNING)
                }
                ShadowsocksTunFdBridgeState.FAILED -> {
                    teardownAfterFailure()
                    fail(ShadowsocksRuntimeError.TunFdHandoffTimedOut(tunFdHandoffTimeoutMillis))
                }
                ShadowsocksTunFdBridgeState.WAITING -> Unit
            }
        }

        return true
    }

    /** Idempotent - stopping an already-STOPPED runtime is a no-op. */
    fun stop() {
        val current = _status.value
        if (current.phase == ShadowsocksRuntimePhase.STOPPED) return
        _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.STOPPING)

        val proc = process
        if (proc != null && proc.isAlive()) {
            proc.requestStop()
            if (proc.waitForExit(gracefulStopTimeoutMillis) == null) {
                proc.forceStop()
                proc.waitForExit(DEFAULT_FORCE_STOP_WAIT_MILLIS)
            }
        }

        protectBridge.stop()
        process = null
        runtimeConfigFile?.let { ShadowsocksRuntimeConfigWriter.delete(it) }
        runtimeConfigFile = null
        _status.value = ShadowsocksRuntimeStatus.IDLE
    }

    private fun onProcessExitedUnexpectedly(exitCode: Int) {
        val phase = _status.value.phase
        if (phase == ShadowsocksRuntimePhase.RUNNING || phase == ShadowsocksRuntimePhase.STARTING) {
            teardownAfterFailure()
            fail(ShadowsocksRuntimeError.ProcessExitedUnexpectedly(exitCode))
        }
        // Already STOPPING/STOPPED - this exit was expected, stop() owns the transition.
    }

    private fun teardownAfterFailure() {
        protectBridge.stop()
        process = null
        runtimeConfigFile?.let { ShadowsocksRuntimeConfigWriter.delete(it) }
        runtimeConfigFile = null
    }

    private fun fail(error: ShadowsocksRuntimeError) {
        _status.value = ShadowsocksRuntimeStatus(ShadowsocksRuntimePhase.FAILED, error)
    }
}
