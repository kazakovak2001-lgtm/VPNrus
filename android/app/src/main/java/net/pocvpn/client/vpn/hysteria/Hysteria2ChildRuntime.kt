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
 * [RealHysteria2ProtectBridge] is the ONLY place that touches the real
 * production class; everywhere else in this file only sees this public
 * interface.
 */
interface Hysteria2ProtectBridge {
    fun start(socketPath: File, protector: (fd: Int) -> Boolean)
    fun stop()
}

/** Reuses the exact real, already-physically-proven SCM_RIGHTS protocol - never reimplemented. */
class RealHysteria2ProtectBridge : Hysteria2ProtectBridge {
    private val delegate = RealShadowsocksVpnProtectBridge()
    override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
        delegate.start(socketPath, ShadowsocksVpnProtector { fd -> protector(fd) })
    }
    override fun stop() = delegate.stop()
}

private const val TAG = "Hysteria2ChildRuntime"
private const val CONFIG_FILENAME = "hysteria2-child-config.json"
private const val PROTECT_SOCKET_FILENAME = "hysteria2-child-protect.sock"
private const val READY_TIMEOUT_MILLIS = 10_000L
private const val DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS = 3_000L
private const val DEFAULT_FORCE_STOP_WAIT_MILLIS = 1_000L

/**
 * Config for the minimal Hysteria2 child - `auth` is a real credential,
 * never logged, never put on argv (see `--config-file`'s own doc in the Go
 * source). [insecure] MUST be `false` for every production call site (B46-4A
 * hard production gate - see docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's
 * "TLS policy" section): [Hysteria2ChildRuntime.start] refuses to launch the
 * child at all when [insecure] is `true`, so a caller cannot silently weaken
 * TLS to make a connection attempt succeed. Only a JVM test targeting a
 * disposable local server may construct this with `insecure = true`, and it
 * must do so directly against [writeConfigFile]-adjacent test doubles, never
 * through the production [Hysteria2ChildRuntime].
 *
 * B46-4A: [socksListen] must be a 127.0.0.1 address (normally
 * [LOCAL_SOCKS_LISTEN], port 0) and [socksUsername]/[socksPassword] are the
 * per-session local SOCKS credentials - all enforced by
 * [Hysteria2ChildRuntime.start]. [toString] never prints any secret.
 */
data class Hysteria2ChildConfig(
    val server: String,
    val auth: String,
    val sni: String,
    val insecure: Boolean,
    val obfsSalamander: String = "",
    val socksListen: String,
    val socksUsername: String,
    val socksPassword: String,
) {
    override fun toString(): String =
        "Hysteria2ChildConfig(server=$server, sni=$sni, insecure=$insecure, socksListen=$socksListen, <secrets redacted>)"
}

sealed interface Hysteria2ChildResult {
    object Ok : Hysteria2ChildResult
    data class Failed(val reason: String) : Hysteria2ChildResult
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
 * `Hysteria2Tun2SocksChildRuntime` already established (deliberately re-derived
 * here rather than sharing a base class, to keep this slice independently
 * reviewable).
 */
class Hysteria2ChildRuntime(
    private val launcher: Hysteria2ChildProcessLauncher = RealHysteria2ChildProcessLauncher(),
    private val protectBridge: Hysteria2ProtectBridge = RealHysteria2ProtectBridge(),
    private val readyTimeoutMillis: Long = READY_TIMEOUT_MILLIS,
    private val gracefulStopTimeoutMillis: Long = DEFAULT_GRACEFUL_STOP_TIMEOUT_MILLIS,
    private val forceStopWaitMillis: Long = DEFAULT_FORCE_STOP_WAIT_MILLIS,
) {
    private val stateLock = Any()
    private var process: Hysteria2ChildProcess? = null
    private var terminalClaimed = true
    private var configFile: File? = null
    private var protectSocketFile: File? = null

    /** Set true the instant the child's own `SOCKS5_LISTENING` log line is observed - diagnostic only. */
    @Volatile var socksReady: Boolean = false
        private set

    /**
     * B46-4A - the `127.0.0.1:<port>` the child actually bound, parsed from its
     * `SOCKS5_LISTENING` line. Non-null only while a started child is running;
     * cleared on stop, failure and unexpected exit.
     */
    @Volatile var boundSocksAddress: String? = null
        private set

    /** Set true the instant the child's own `connected: udpEnabled=...` log line is observed (real QUIC handshake success) - diagnostic only. */
    @Volatile var quicConnected: Boolean = false
        private set

    var onUnexpectedExit: ((exitCode: Int) -> Unit)? = null

    fun isRunning(): Boolean = synchronized(stateLock) { process?.isAlive() == true }

    fun start(config: Hysteria2ChildConfig, binaryPath: String, workingDir: File, protector: (fd: Int) -> Boolean): Hysteria2ChildResult {
        // B46-4A hard production gate: production must not use insecure=true
        // (see Hysteria2ChildConfig.insecure's own doc). This is enforced
        // HERE, not only at the VpnService call site, so no future caller of
        // this runtime can accidentally bypass it.
        if (config.insecure) {
            return Hysteria2ChildResult.Failed("insecure TLS is not permitted for a production Hysteria2 child")
        }
        // B46-4A - never launch an anonymous or non-loopback local SOCKS listener.
        if (config.socksListen != LOCAL_SOCKS_LISTEN && parseLoopbackSocksAddress(config.socksListen) == null) {
            return Hysteria2ChildResult.Failed("socksListen must be a 127.0.0.1 address")
        }
        if (config.socksUsername.isEmpty() || config.socksPassword.isEmpty()) {
            return Hysteria2ChildResult.Failed("missing local socks credentials")
        }
        synchronized(stateLock) {
            if (process != null) return Hysteria2ChildResult.Failed("child already running")
        }
        workingDir.mkdirs()

        val protectSocketPath = File(workingDir, PROTECT_SOCKET_FILENAME)
        protectSocketFile = protectSocketPath
        try {
            protectBridge.start(protectSocketPath) { fd -> protector(fd) }
        } catch (t: Throwable) {
            return Hysteria2ChildResult.Failed("protect bridge bind failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        val configPath = File(workingDir, CONFIG_FILENAME)
        configFile = configPath
        try {
            writeConfigFile(configPath, config, protectSocketPath)
        } catch (t: Throwable) {
            protectBridge.stop()
            return Hysteria2ChildResult.Failed("config file write failed: ${t.javaClass.simpleName}: ${t.message}")
        }

        socksReady = false
        quicConnected = false
        boundSocksAddress = null
        val launched = try {
            launcher.launch(binaryPath, listOf("--config-file", configPath.absolutePath))
        } catch (t: Throwable) {
            protectBridge.stop()
            configPath.delete()
            return Hysteria2ChildResult.Failed("failed to launch child process: ${t.javaClass.simpleName}: ${t.message}")
        }

        val readyLatch = java.util.concurrent.CountDownLatch(1)
        // B46-4A - the readiness line must carry the real bound 127.0.0.1:<port>;
        // a missing or invalid address fails startup closed below.
        var reportedSocksAddress: String? = null
        launched.attachLogWatcher { line ->
            if (line.contains("SOCKS5_LISTENING") && readyLatch.count > 0) {
                reportedSocksAddress = parseSocksListeningLine(line)
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
            return Hysteria2ChildResult.Failed("child did not report SOCKS5_LISTENING within ${readyTimeoutMillis}ms")
        }
        val bound = reportedSocksAddress
        if (bound == null) {
            stopLaunchedProcess(launched)
            protectBridge.stop()
            configPath.delete()
            socksReady = false
            return Hysteria2ChildResult.Failed("child reported SOCKS5_LISTENING without a valid 127.0.0.1 address")
        }
        boundSocksAddress = bound

        synchronized(stateLock) {
            process = launched
            terminalClaimed = false
        }
        launched.onExit { code -> handleChildExit(code) }
        Log.i(TAG, "hysteria child started, socksReady=$socksReady quicConnected=$quicConnected")
        return Hysteria2ChildResult.Ok
    }

    fun stop(): Hysteria2ChildResult {
        val current: Hysteria2ChildProcess?
        synchronized(stateLock) {
            current = process
            if (current == null) {
                cleanupArtifacts()
                return Hysteria2ChildResult.Ok
            }
            terminalClaimed = true
            process = null
        }
        stopLaunchedProcess(current!!)
        cleanupArtifacts()
        return Hysteria2ChildResult.Ok
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
        boundSocksAddress = null
    }

    private fun stopLaunchedProcess(launched: Hysteria2ChildProcess) {
        if (!launched.isAlive()) return
        launched.requestStop()
        val exited = launched.waitForExit(gracefulStopTimeoutMillis)
        if (exited == null) {
            Log.w(TAG, "hysteria child did not exit gracefully within ${gracefulStopTimeoutMillis}ms - forcing")
            launched.forceStop()
            launched.waitForExit(forceStopWaitMillis)
        }
    }

    private fun writeConfigFile(path: File, config: Hysteria2ChildConfig, protectSocketPath: File) {
        val json = JSONObject().apply {
            put("server", config.server)
            put("auth", config.auth)
            put("sni", config.sni)
            put("insecure", config.insecure)
            put("obfsSalamander", config.obfsSalamander)
            put("socksListen", config.socksListen)
            put("protectPath", protectSocketPath.absolutePath)
            put("socksUsername", config.socksUsername)
            put("socksPassword", config.socksPassword)
        }
        path.writeText(json.toString())
        path.setReadable(false, false)
        path.setWritable(false, false)
        path.setReadable(true, true)
        path.setWritable(true, true)
    }
}

/** Small internal extension so [Hysteria2ChildRuntime] can watch log lines without Hysteria2ChildProcess exposing raw streams - kept private to this file's own launcher wiring via a side-channel callback list on RealHysteria2ChildProcess would over-complicate the small interface; instead this reuses `onExit`-adjacent Log.d output is already captured by RealHysteria2ChildProcessLauncher's own drainStreamAsync, so this function attaches nothing extra when using the real launcher and is a no-op fake-friendly seam for tests. */
private fun Hysteria2ChildProcess.attachLogWatcher(onLine: (String) -> Unit) {
    if (this is LogLineObservable) {
        addLogLineListener(onLine)
    }
}

/** Implemented by [RealHysteria2ChildProcess]-shaped real processes that can report their own stdout/stderr lines back to [Hysteria2ChildRuntime] for readiness detection. */
interface LogLineObservable {
    fun addLogLineListener(listener: (String) -> Unit)
}
