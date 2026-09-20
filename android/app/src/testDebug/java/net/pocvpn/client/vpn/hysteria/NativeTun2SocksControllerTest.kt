package net.pocvpn.client.vpn.hysteria

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Records calls and returns a scripted result - never touches JNI/System.loadLibrary. */
private class FakeNativeTun2SocksLibrary(
    private val startResult: NativeBridgeResult = NativeBridgeResult.Ok,
    private val stopResult: NativeBridgeResult = NativeBridgeResult.Ok,
) : NativeTun2SocksLibrary {
    var startCalls = 0
    var stopCalls = 0
    private var startedNatively = false

    override fun start(fd: Int, mtu: Int, socksAddr: String): NativeBridgeResult {
        startCalls++
        if (startResult is NativeBridgeResult.Ok) startedNatively = true
        return startResult
    }

    override fun stop(): NativeBridgeResult {
        stopCalls++
        startedNatively = false
        return stopResult
    }

    override fun isStarted(): Boolean = startedNatively
}

/**
 * B46-3A test coverage: repeated-start rejection, stop idempotency, invalid
 * fd/mtu/socks-address, and native error-code mapping - all exercised
 * against the Kotlin-side [NativeTun2SocksController] with a
 * [FakeNativeTun2SocksLibrary], so none of this depends on the locally-built
 * `.so`s being present in the JVM unit test environment. JNI-load-failure
 * mapping itself is covered separately in [NativeTun2SocksBridgeTest]
 * against the real [NativeTun2SocksBridge] singleton.
 */
class NativeTun2SocksControllerTest {

    @Test
    fun `initial state is not started`() {
        val controller = NativeTun2SocksController(FakeNativeTun2SocksLibrary())
        assertFalse(controller.isStarted())
    }

    @Test
    fun `valid start succeeds and reports started`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)

        val result = controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        assertEquals(NativeBridgeResult.Ok, result)
        assertTrue(controller.isStarted())
        assertEquals(1, fake.startCalls)
    }

    @Test
    fun `second start while already started fails deterministically without reaching native layer`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)
        controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        val second = controller.start(fd = 43, mtu = 1500, socksAddr = "127.0.0.1:41080")

        assertEquals(NativeBridgeResult.Failed("bridge already started"), second)
        // Rejected in Kotlin before ever calling into the (fake) native layer again.
        assertEquals(1, fake.startCalls)
    }

    @Test
    fun `stop is idempotent`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)

        val first = controller.stop()
        val second = controller.stop()

        assertEquals(NativeBridgeResult.Ok, first)
        assertEquals(NativeBridgeResult.Ok, second)
        assertFalse(controller.isStarted())
    }

    @Test
    fun `stop after start resets local state`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)
        controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        controller.stop()

        assertFalse(controller.isStarted())
        assertEquals(1, fake.stopCalls)
        // A fresh start is allowed again after a stop.
        val restarted = controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")
        assertEquals(NativeBridgeResult.Ok, restarted)
    }

    @Test
    fun `invalid fd is rejected before reaching native layer`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)

        val result = controller.start(fd = -1, mtu = 1500, socksAddr = "127.0.0.1:41080")

        assertEquals(NativeBridgeResult.Failed("invalid fd"), result)
        assertEquals(0, fake.startCalls)
        assertFalse(controller.isStarted())
    }

    @Test
    fun `invalid mtu is rejected before reaching native layer`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)

        val zero = controller.start(fd = 42, mtu = 0, socksAddr = "127.0.0.1:41080")
        val negative = controller.start(fd = 42, mtu = -10, socksAddr = "127.0.0.1:41080")

        assertEquals(NativeBridgeResult.Failed("invalid mtu"), zero)
        assertEquals(NativeBridgeResult.Failed("invalid mtu"), negative)
        assertEquals(0, fake.startCalls)
    }

    @Test
    fun `empty socks address is rejected before reaching native layer`() {
        val fake = FakeNativeTun2SocksLibrary()
        val controller = NativeTun2SocksController(fake)

        val result = controller.start(fd = 42, mtu = 1500, socksAddr = "")

        assertEquals(NativeBridgeResult.Failed("empty socks address"), result)
        assertEquals(0, fake.startCalls)
    }

    @Test
    fun `native error mapping is passed through unchanged from the library`() {
        val fake = FakeNativeTun2SocksLibrary(startResult = NativeBridgeResult.Failed("engine start failed"))
        val controller = NativeTun2SocksController(fake)

        val result = controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        assertEquals(NativeBridgeResult.Failed("engine start failed"), result)
        assertFalse(controller.isStarted())
    }

    @Test
    fun `native stop failure is still reported and local state still clears`() {
        val fake = FakeNativeTun2SocksLibrary(stopResult = NativeBridgeResult.Failed("engine stop failed"))
        val controller = NativeTun2SocksController(fake)
        controller.start(fd = 42, mtu = 1500, socksAddr = "127.0.0.1:41080")

        val result = controller.stop()

        assertEquals(NativeBridgeResult.Failed("engine stop failed"), result)
        // Local bookkeeping still clears so a caller isn't wedged forever by
        // a native-side stop failure - matches B46HysteriaRuntime's own
        // "best-effort stop, always finish tearing down" convention.
        assertFalse(controller.isStarted())
    }
}
