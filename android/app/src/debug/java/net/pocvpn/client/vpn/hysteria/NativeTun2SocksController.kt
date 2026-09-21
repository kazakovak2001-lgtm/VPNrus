package net.pocvpn.client.vpn.hysteria

/**
 * B46-3A - abstraction over the raw JNI primitive ([NativeTun2SocksBridge]),
 * so [NativeTun2SocksController]'s lifecycle rules are unit-testable
 * without the locally-built `.so`s present - mirrors
 * `B46Tun2SocksBridge`/`FakeB46Tun2SocksBridge`'s own split in the B46-2P
 * harness (`b46harness/src/main/java/net/pocvpn/b46harness/B46Tun2SocksBridgeAdapter.kt`).
 */
interface NativeTun2SocksLibrary {
    fun start(fd: Int, mtu: Int, socksAddr: String): NativeBridgeResult
    fun stop(): NativeBridgeResult
    fun isStarted(): Boolean
}

/** Delegates straight to the real JNI-backed [NativeTun2SocksBridge] singleton. */
object RealNativeTun2SocksLibrary : NativeTun2SocksLibrary {
    override fun start(fd: Int, mtu: Int, socksAddr: String): NativeBridgeResult =
        NativeTun2SocksBridge.start(fd, mtu, socksAddr)

    override fun stop(): NativeBridgeResult = NativeTun2SocksBridge.stop()

    override fun isStarted(): Boolean = NativeTun2SocksBridge.isStarted()
}

/**
 * B46-3A - Kotlin-side lifecycle gate in front of the native bridge.
 * Duplicates the same input validation the Go side already enforces
 * (`research/b46-3a-hysteria-native-bridge/native/main.go`) so a bad call
 * never even reaches the JNI boundary, and tracks start/stop state locally
 * so "started twice" is rejected deterministically regardless of whether
 * the native library is present (see [NativeTun2SocksLibrary]).
 *
 * FD ownership contract (see [NativeTun2SocksBridge]'s own doc, load-bearing,
 * reused from B46-2P/B46-2C): [fd] must already be a duplicate of the
 * VpnService's TUN fd. This class never dups or closes the original.
 */
class NativeTun2SocksController(
    private val library: NativeTun2SocksLibrary = RealNativeTun2SocksLibrary,
) {
    private var startedLocally = false

    fun start(fd: Int, mtu: Int, socksAddr: String): NativeBridgeResult {
        if (startedLocally) {
            return NativeBridgeResult.Failed("bridge already started")
        }
        if (fd < 0) {
            return NativeBridgeResult.Failed("invalid fd")
        }
        if (mtu <= 0) {
            return NativeBridgeResult.Failed("invalid mtu")
        }
        if (socksAddr.isEmpty()) {
            return NativeBridgeResult.Failed("empty socks address")
        }

        val result = library.start(fd, mtu, socksAddr)
        if (result is NativeBridgeResult.Ok) {
            startedLocally = true
        }
        return result
    }

    /** Idempotent: safe to call when not started. */
    fun stop(): NativeBridgeResult {
        val result = library.stop()
        startedLocally = false
        return result
    }

    fun isStarted(): Boolean = startedLocally && library.isStarted()
}
