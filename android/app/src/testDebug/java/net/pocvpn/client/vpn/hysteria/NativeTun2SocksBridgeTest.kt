package net.pocvpn.client.vpn.hysteria

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-3A - exercises the REAL [NativeTun2SocksBridge] singleton (not a
 * fake). In the JVM unit test environment `System.loadLibrary` always
 * throws `UnsatisfiedLinkError` (no real Android runtime, no `.so`s on the
 * JVM's native library path), which deterministically proves the "JNI load
 * failure mapping" requirement: every call must come back as a typed
 * [NativeBridgeResult.Failed], never a raw exception out of this class and
 * never a crash of the test JVM itself.
 */
class NativeTun2SocksBridgeTest {

    @Test
    fun `start maps a missing native library to a typed failure, never throws`() {
        val result = NativeTun2SocksBridge.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        assertTrue(result is NativeBridgeResult.Failed)
        val reason = (result as NativeBridgeResult.Failed).reason
        assertTrue(
            "expected failure reason to mention the native library load failure, was: $reason",
            reason.contains("native library not loaded"),
        )
    }

    @Test
    fun `stop is a harmless no-op when the native library never loaded`() {
        val result = NativeTun2SocksBridge.stop()

        assertTrue(result is NativeBridgeResult.Ok)
    }

    @Test
    fun `isStarted is false when the native library never loaded`() {
        assertFalse(NativeTun2SocksBridge.isStarted())
    }
}
