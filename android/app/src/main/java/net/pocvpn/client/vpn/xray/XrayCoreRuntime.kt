package net.pocvpn.client.vpn.xray

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.pocvpn.client.BuildConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Abstraction over the pinned AndroidLibXrayLite AAR's
 * libv2ray.Libv2ray/CoreController - see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md
 * (§7, verified exported API) for the exact native method signatures this
 * wraps. Exists so [NovaXrayVpnService]'s start/stop/duplicate-start/
 * teardown-ordering logic can be unit-tested on the JVM with a fake runtime -
 * the real implementation loads a native .so via JNI, which a plain JVM unit
 * test cannot do.
 */
interface XrayCoreRuntime {
    /**
     * Idempotent, must be called at least once (from any real Context) before
     * the first [startLoop] call. Mirrors v2rayNG's CoreNativeManager.initCoreEnv:
     * go.Seq.setContext(...) + Libv2ray.initCoreEnv(assetPath, deviceId).
     */
    fun ensureCoreEnvInitialized(context: Context)

    /** True once startLoop has returned without throwing and stopLoop has not been called since. */
    val isRunning: Boolean

    /** Mirrors CoreController.startLoop(configContent, tunFd). Throws on failure - never returns a false "ok". */
    @Throws(Exception::class)
    fun startLoop(configContent: String, tunFd: Int)

    /** Mirrors CoreController.stopLoop(). Safe to call when not running (no-op). */
    fun stopLoop()

    /**
     * B21-fix - mirrors CoreController.measureDelay(url): dials the currently
     * running core's own outbound and returns a real round-trip latency in
     * ms, throwing if the dial/request itself fails. This is the ONE genuine
     * "does this outbound actually pass traffic" signal the AndroidLibXrayLite
     * AAR exports (verified via javap against the shipped classes.jar - there
     * is no separate socket/protect callback in this API surface) - see
     * [XrayDataPlaneReadinessCheck], which wraps this with a bounded timeout
     * and turns it into a typed result. Transport-agnostic: the same call
     * works unmodified for REALITY/TLS_TCP/QUIC because each renders exactly
     * one outbound into the running core - no per-transport branching needed.
     */
    @Throws(Exception::class)
    suspend fun measureDelay(testUrl: String): Long
}

/**
 * Real [XrayCoreRuntime] backed by the pinned AAR. Holds exactly one
 * `libv2ray.CoreController` for this process's lifetime - a fresh instance is
 * NOT created per connect() attempt, matching v2rayNG's own
 * CoreServiceManager pattern (one coreController field, reused across
 * start/stop cycles) confirmed in docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md.
 */
class LibXrayCoreRuntime : XrayCoreRuntime {

    private val envInitialized = AtomicBoolean(false)

    private val controller: libv2ray.CoreController by lazy {
        libv2ray.Libv2ray.newCoreController(DiagnosticsCoreCallbackHandler)
    }

    override fun ensureCoreEnvInitialized(context: Context) {
        if (!envInitialized.compareAndSet(false, true)) return
        try {
            go.Seq.setContext(context.applicationContext)
            val assetDir = java.io.File(context.noBackupFilesDir, "xray-assets").apply { mkdirs() }
            // deviceId personalizes XUDP session base keys only (an anti-fingerprinting
            // refinement, not connection-critical, not a credential) - this adapter shell
            // does not implement v2rayNG's per-device derivation yet, so this is left
            // empty rather than fabricating an unverified algorithm.
            libv2ray.Libv2ray.initCoreEnv(assetDir.absolutePath, "")
        } catch (t: Throwable) {
            envInitialized.set(false)
            throw t
        }
    }

    override val isRunning: Boolean
        get() = controller.isRunning

    override fun startLoop(configContent: String, tunFd: Int) {
        controller.startLoop(configContent, tunFd)
    }

    override fun stopLoop() {
        if (controller.isRunning) {
            controller.stopLoop()
        }
    }

    override suspend fun measureDelay(testUrl: String): Long =
        withContext(Dispatchers.IO) { controller.measureDelay(testUrl) }

    /**
     * B21-fix - root-caused the QUIC false-positive Connected report: this
     * handler used to be a NoopCoreCallbackHandler that discarded every
     * xray-core startup/shutdown/status event, so the ONE channel the Go
     * runtime had for reporting a config-load or dial failure was silently
     * thrown away client-side. Now forwards into [XrayCoreDiagnostics] -
     * DEBUG builds only ([BuildConfig.DEBUG], compiled out of release), and
     * even there [XrayCoreDiagnostics.record] sanitizes/bounds every message
     * before it is kept. Return values are unchanged (0 - AndroidLibXrayLite
     * does not currently inspect them).
     */
    private object DiagnosticsCoreCallbackHandler : libv2ray.CoreCallbackHandler {
        override fun startup(): Long {
            if (BuildConfig.DEBUG) XrayCoreDiagnostics.record("startup", null)
            return 0
        }

        override fun shutdown(): Long {
            if (BuildConfig.DEBUG) XrayCoreDiagnostics.record("shutdown", null)
            return 0
        }

        override fun onEmitStatus(l: Long, s: String?): Long {
            if (BuildConfig.DEBUG) XrayCoreDiagnostics.record("status", s)
            return 0
        }
    }
}
