package net.pocvpn.b46harness

/** Result of a tun2socks bridge start/stop call. */
internal sealed interface B46Tun2SocksResult {
    object Ok : B46Tun2SocksResult
    data class Failed(val reason: String) : B46Tun2SocksResult
}

/**
 * Abstraction over the real gomobile-bound `bridge.Bridge` class, so
 * [B46HysteriaRuntime]'s orchestration logic is unit-testable against a
 * fake without the (large, gitignored, locally-built) AAR present - see
 * [FakeB46Tun2SocksBridge] in the `test` source set.
 */
internal interface B46Tun2SocksBridge {
    /** [fd] MUST already be a duplicate of the VpnService's TUN fd - see `tun2socks-bridge/bridge.go`'s ownership contract. */
    fun start(fd: Int, mtu: Int, socksAddr: String): B46Tun2SocksResult
    fun stop(): B46Tun2SocksResult
}

/**
 * B46-2P - loads the real gomobile-bound `bridge.Bridge` class (from
 * `research/b46-2p-android-physical/tun2socks-bridge/`, packaged as
 * `android/app/src/debug/local-libs/b46-tun2socks.aar`, only
 * `debugImplementation`'d when that file exists on disk - see
 * `android/app/build.gradle.kts`) via REFLECTION, never a compile-time
 * import.
 *
 * This is deliberate, not a style preference: `b46-tun2socks.aar` is a
 * large, locally-built, gitignored research artifact that will not exist
 * in CI or on a fresh checkout before someone runs the `gomobile bind`
 * build. A compile-time `import bridge.Bridge` would make ordinary `debug`
 * source compilation depend on that artifact's presence, breaking CI/clean
 * checkouts. Reflection keeps compilation truthful regardless of whether
 * the AAR exists, and this adapter fails closed with a typed
 * [B46Tun2SocksResult.Failed] rather than a `NoClassDefFoundError`
 * surfacing raw.
 */
internal class RealB46Tun2SocksBridge : B46Tun2SocksBridge {

    private companion object {
        const val BRIDGE_CLASS = "bridge.Bridge"
    }

    override fun start(fd: Int, mtu: Int, socksAddr: String): B46Tun2SocksResult {
        return try {
            val cls = Class.forName(BRIDGE_CLASS)
            // Real signature confirmed via `javap -p bridge.Bridge` against
            // the committed AAR: gobind lowercases the Go exported method
            // name for its Java binding (StartBridge -> startBridge), and
            // maps Go's platform `int` to Java `long` (never `int`) -
            // `startBridge(long, long, String) throws Exception`. Both were
            // wrong assumptions in an earlier version of this adapter,
            // caught by a real physical run (NoSuchMethodException).
            val method = cls.getMethod("startBridge", Long::class.javaPrimitiveType, Long::class.javaPrimitiveType, String::class.java)
            // void-returning: invoke() returns null on success, or throws
            // InvocationTargetException wrapping the real Go error on failure.
            method.invoke(null, fd.toLong(), mtu.toLong(), socksAddr)
            B46Tun2SocksResult.Ok
        } catch (t: java.lang.reflect.InvocationTargetException) {
            B46Tun2SocksResult.Failed(t.targetException?.message ?: t.message ?: "unknown startBridge failure")
        } catch (t: ReflectiveOperationException) {
            B46Tun2SocksResult.Failed(
                "bridge.Bridge class/method not found - was b46-tun2socks.aar built and placed at " +
                    "b46harness/local-libs/b46-tun2socks.aar? (${t.javaClass.simpleName}: ${t.message})",
            )
        } catch (t: Throwable) {
            B46Tun2SocksResult.Failed("${t.javaClass.simpleName}: ${t.message}")
        }
    }

    override fun stop(): B46Tun2SocksResult {
        return try {
            val cls = Class.forName(BRIDGE_CLASS)
            val method = cls.getMethod("stopBridge")
            method.invoke(null)
            B46Tun2SocksResult.Ok
        } catch (t: java.lang.reflect.InvocationTargetException) {
            B46Tun2SocksResult.Failed(t.targetException?.message ?: t.message ?: "unknown stopBridge failure")
        } catch (t: ReflectiveOperationException) {
            B46Tun2SocksResult.Failed("${t.javaClass.simpleName}: ${t.message}")
        } catch (t: Throwable) {
            B46Tun2SocksResult.Failed("${t.javaClass.simpleName}: ${t.message}")
        }
    }
}
