package net.pocvpn.client.vpn.xray

import android.content.Context
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
     * B33 - mirrors the pinned AAR's real `CoreController.measureDelay(url)`
     * native method (see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md §7 for the
     * verified exported API surface) - dials [url] through the JUST-STARTED
     * core's own configured outbound/routing, exactly like v2rayNG's own
     * "test configuration" feature. Returns the measured delay in
     * milliseconds on success; throws on failure (connection refused, no
     * handshake, timeout inside the native implementation, etc.) - never a
     * negative/sentinel "ok" value. This is the ONE real, production-capable
     * signal [XrayCoreController.requestStart] uses to confirm the tunnel is
     * genuinely usable beyond local process startup - see that function's
     * own docs.
     */
    @Throws(Exception::class)
    fun measureDelay(url: String): Long

    /**
     * B-WL7 - mirrors the pinned AAR's `CoreController.queryAllOutboundTrafficStats()`:
     * reads AND resets every outbound byte counter, returning
     * `tag,direction,value;...` (empty when stats are off or nothing moved).
     * See [XrayTrafficCounters] for how the resetting readings are summed.
     */
    fun queryAllOutboundTrafficStats(): String = ""
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
        libv2ray.Libv2ray.newCoreController(NoopCoreCallbackHandler)
    }

    /** Chooses the geo asset directory (user-activated dataset, else the bundled one, else the plain root). */
    @Volatile
    private var geoDirs: GeoAssetDirProvider? = null

    override fun ensureCoreEnvInitialized(context: Context) {
        if (!envInitialized.compareAndSet(false, true)) {
            refreshGeoAssetDirectory()
            return
        }
        try {
            go.Seq.setContext(context.applicationContext)
            val assetRoot = java.io.File(context.noBackupFilesDir, "xray-assets").apply { mkdirs() }
            // Settings -> GeoData: the directory handed to the core is a verified `geo-<id>` dataset
            // directory holding geoip.dat and geosite.dat at its top level (the user-activated one, else
            // the one staged from the APK's bundled assets). It never throws and never fails the start:
            // on any problem the directory is the plain `xray-assets` root, i.e. what this call used before.
            val provider = GeoAssetDirProvider(assetRoot, context.assets.asGeoAssetSource()) { line ->
                android.util.Log.i("GeoData", line)
            }
            geoDirs = provider
            // Geo data must never block a VPN start: any unexpected failure here means the plain root.
            val assetDir = try {
                provider.resolveInitial().directory
            } catch (t: Throwable) {
                android.util.Log.w("GeoData", "geo data: resolve failed (${t.javaClass.simpleName}); using plain asset root")
                assetRoot
            }
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

    /**
     * Later starts in the same process: when the user activated a different dataset since the last start and
     * the core is NOT running, point the core environment at it before the next `startLoop`. A running core is
     * never re-pointed (there is no hot reload). Best effort: any failure keeps the directory already in use.
     */
    private fun refreshGeoAssetDirectory() {
        val provider = geoDirs ?: return
        try {
            if (controller.isRunning) return
            val changed = provider.changedResolution() ?: return
            libv2ray.Libv2ray.initCoreEnv(changed.directory.absolutePath, "")
        } catch (t: Throwable) {
            android.util.Log.w("GeoData", "geo data: could not refresh asset directory (${t.javaClass.simpleName})")
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

    override fun measureDelay(url: String): Long = controller.measureDelay(url)

    override fun queryAllOutboundTrafficStats(): String = controller.queryAllOutboundTrafficStats() ?: ""

    /**
     * This adapter shell does not yet surface core lifecycle events anywhere
     * (no UI/notification depends on them) - a real handler that only logs
     * would risk becoming the one place a future change accidentally logs
     * config content. Every callback here is intentionally inert.
     */
    private object NoopCoreCallbackHandler : libv2ray.CoreCallbackHandler {
        override fun startup(): Long = 0
        override fun shutdown(): Long = 0
        override fun onEmitStatus(l: Long, s: String?): Long = 0
    }
}
