package net.pocvpn.client.vpn.hysteria

import android.util.Log
import java.io.File
import net.pocvpn.client.vpn.shadowsocks.RealShadowsocksVpnProtectBridge
import net.pocvpn.client.vpn.shadowsocks.ShadowsocksVpnProtector
import org.json.JSONObject

/**
 * Public seam wrapping the real, `internal`-visibility production protect
 * bridge (`net.pocvpn.client.vpn.shadowsocks.ShadowsocksVpnProtectBridge`/
 * `RealShadowsocksVpnProtectBridge`) - a thin adapter, not a
 * reimplementation, needed only because Kotlin does not allow a public
 * class to expose an `internal` type in its own public signature.
 * [RealHysteriaProtectBridge] is the ONLY place that touches the real
 * production class; everywhere else in this file only sees this public
 * interface.
 */
interface HysteriaProtectBridge {
    fun start(socketPath: File, protector: (fd: Int) -> Boolean)
    fun stop()
}

/** Reuses the exact real, already-physically-proven SCM_RIGHTS protocol - never reimplemented. */
class RealHysteriaProtectBridge : HysteriaProtectBridge {
    private val delegate = RealShadowsocksVpnProtectBridge()
    override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
        delegate.start(socketPath, ShadowsocksVpnProtector { fd -> protector(fd) })
    }
    override fun stop() = delegate.stop()
}

private const val TAG = "HysteriaChildRuntime"
private const val CONFIG_FILENAME = "b46-3c-hysteria-config.json"
private const val PROTECT_SOCKET_FILENAME = "b46-3c-hysteria-protect.sock"
private const val READY_TIMEOUT_MILLIS = 10_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/** Config for the minimal Hysteria2 child - `auth` is a real credential, never logged, never put on argv (see `--config-file`'s own doc in the Go source). */
data class HysteriaChildConfig(
    val server: String,
    val auth: String,
    val sni: String,
    val insecure: Boolean,
    val obfsSalamander: String = "",
    val socksListen: String,
)

sealed interface HysteriaChildResult {
    object Ok : HysteriaChildResult
    data class Failed(val reason: String) : HysteriaChildResult
}

/**
 * B46-3C - orchestrates the process-isolated minimal Hysteria2 child:
 * write its non-argv config file (mode 600, deleted on stop), start the
 * REAL production protect(fd) bridge
 * (`net.pocvpn.client.vpn.shadowsocks.RealShadowsocksVpnProtectBridge` -
 * reused directly, not reimplemented, per the task's own instruction),
 * spawn the child, wait for its own `SOCKS5_LISTENING` readiness log line
 * (bounded), and own its stop/cleanup - same "one class owns lifecycle
 * ordering, unexpected-death-aware" shape B46-3B's own
 * `Tun2SocksChildRuntime` already established (deliberately re-derived
 * here rather than sharing a base class, to keep this slice independently
 * reviewable).
 */
class HysteriaChildRuntime(
    private val launcher: HysteriaChildProcessLauncher = RealHysteriaChildProcessLauncher(),
    private val protectBridge: HysteriaProtectBridge = RealHysteriaProtectBridge(),
    private val readyTimeoutMillis: Long = READY_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val forceStopWaitMillis: Long = DEFAULT_FORCE_STOP_WAIT_MILLIS,
) {
    private val stateLock = Any()
    private var process: HysteriaChildProcess? = null
    private var terminalClaimed = true
    private var configFile: File? = null
    private var protectSocketFile: File? = null

    /** Set true the instant the child's own `SOCKS5_LISTENING` log line is observed - diagnostic only. */
    @Volatile var socksReady: Boolean = false
        private set

    /** Set true the instant the child's own `connected: udpEnabled=...` log line is observed (real QUIC handshake success) - diagnostic only. */
    @Volatile var quicConnected: Boolean = false
        private set

    var onUnexpectedExit: ((exitCode: Int) -> Unit)? = null

    fun isRunning(): Boolean = synchronized(stateLock) { process?.isAlive() == true }

    fun start(config: HysteriaChildConfig, binaryPath: String, workingDir: File, protector: (fd: Int) -> Boolean): HysteriaChildResult {
        synchronized(stateLock) {
            if (process != null) return HysteriaChildResult.Failed("child already running")
        }
        workingDir.mkdirs()

        val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
        protectSocketFile = protectSocketPath
        try {
            protectBridge.start(protectSocketPath) { fd -> protector(fd) }
        } catch (t: Throwable) {
            return HysteriaChildResult.Failed("protect bridge bind failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        val configPath = File(workingDir, CONFIG_FILENAME)
        configFile = configPath
        try {
            writeConfigFile(configPath, config, protectSocketPath)
        } catch (t: Throwable) {
            protectBridge.stop()
            return HysteriaChildResult.Failed("config file write failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        socksReady = false
        quicConnected = false
        val launched = try {
            launcher.launch(binaryPath, listOf("--config-file", configPath.absolutePath))
        } catch (t: Throwable) {
            protectBridge.stop()
            configPath.delete()
            return HysteriaChildResult.Failed("failed to launch child process: ${t.javaClass.simpleName}: ${t.message}")
        }

        val readyLatch = java.util.concurrent.CountDownLatch(1)
        launched.attachLogWatcher { line ->
            if (line.contains("SOCKS5_LISTENING")) {
                socksReady = true
                readyLatch.countDown()
            }
            if (line.contains("connected: udpEnabled")) {
                quicConnected = true
            }
        }

        val becameReady = readyLatch.await(readyTimeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
        if (!becameReady) {
            stopLaunchedProcess(launched)
            protectBridge.stop()
            configPath.delete()
            return HysteriaChildResult.Failed("child did not report SOCKS5_LISTENING within ${readyTimeoutMillis}ms")
        }

        synchronized(stateLock) {
            process = launched
            terminalClaimed = false
        }
        launched.onExit { code -> handleChildExit(code) }
        Log.i(TAG, "hysteria child started, socksReady=$socksReady quicConnected=$quicConnected")
        return HysteriaChildResult.Ok
    }

    fun stop(): HysteriaChildResult {
        val current: HysteriaChildProcess?
        synchronized(stateLock) {
            current = process
            if (current == null) {
                cleanupArtifacts()
                return HysteriaChildResult.Ok
            }
            terminalClaimed = true
            process = null
        }
        stopLaunchedProcess(current!!)
        cleanupArtifacts()
        return HysteriaChildResult.Ok
    }

    private fun handleChildExit(exitCode: Int) {
        val shouldNotify = synchronized(stateLock) {
            if (terminalClaimed) {
                false
            } else {
                terminalClaimed = true
                process = null
                true
            }
        }
        if (!shouldNotify) return
        Log.w(TAG, "hysteria child exited unexpectedly: code=$exitCode")
        cleanupArtifacts()
        onUnexpectedExit?.invoke(exitCode)
    }

    private fun cleanupArtifacts() {
        protectBridge.stop()
        configFile?.delete()
        protectSocketFile?.delete()
        configFile = null
        protectSocketFile = null
        socksReady = false
        quicConnected = false
    }

    private fun stopLaunchedProcess(launched: HysteriaChildProcess) {
        if (!launched.isAlive()) return
        launched.requestStop()
        val exited = launched.waitForExit(gracefulStopTimeoutMillis)
        if (exited == null) {
            Log.w(TAG, "hysteria child did not exit gracefully within ${gracefulStopTimeoutMillis}ms - forcing")
            launched.forceStop()
            launched.waitForExit(forceStopWaitMillis)
        }
    }

    private fun writeConfigFile(path: File, config: HysteriaChildConfig, protectSocketPath: File) {
        val json = JSONObject().apply {
            put("server", config.server)
            put("auth", config.auth)
            put("sni", config.sni)
            put("insecure", config.insecure)
            put("obfsSalamander", config.obfsSalamander)
            put("socksListen", config.socksListen)
            put("protectPath", protectSocketPath.absolutePath)
        }
        path.writeText(json.toString())
        path.setReadable(false, false)
        path.setWritable(false, false)
        path.setReadable(true, true)
        path.setWritable(true, true)
    }
}

/** Small internal extension so [HysteriaChildRuntime] can watch log lines without HysteriaChildProcess exposing raw streams - kept private to this file's own launcher wiring via a side-channel callback list on RealHysteriaChildProcess would over-complicate the small interface; instead this reuses `onExit`-adjacent Log.d output is already captured by RealHysteriaChildProcessLauncher's own drainStreamAsync, so this function attaches nothing extra when using the real launcher and is a no-op fake-friendly seam for tests. */
private fun HysteriaChildProcess.attachLogWatcher(onLine: (String) -> Unit) {
    if (this is LogLineObservable) {
        addLogLineListener(onLine)
    }
}

/** Implemented by [RealHysteriaChildProcess]-shaped real processes that can report their own stdout/stderr lines back to [HysteriaChildRuntime] for readiness detection. */
interface LogLineObservable {
    fun addLogLineListener(listener: (String) -> Unit)
}
