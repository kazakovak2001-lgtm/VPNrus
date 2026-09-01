package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B21-fix - proves [XrayDataPlaneReadinessCheck]'s three outcomes directly
 * against a fake [XrayCoreRuntime], independent of [XrayCoreController]'s own
 * wiring (covered separately in [XrayCoreControllerTest]).
 */
class XrayDataPlaneReadinessCheckTest {

    @Test
    fun `a fast successful measureDelay is Ready with the real latency`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayResult = 123L)

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L)

        assertEquals(XrayDataPlaneReadiness.Ready(123L), result)
        assertEquals(1, runtime.measureDelayCallCount)
    }

    @Test
    fun `measureDelay throwing is Failed with the exception's class name and sanitized message`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException("dial failed"))

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L)

        assertEquals(XrayDataPlaneReadiness.Failed("IllegalStateException: dial failed"), result)
    }

    @Test
    fun `measureDelay throwing with no message is Failed with just the class name`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException())

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L)

        assertEquals(XrayDataPlaneReadiness.Failed("IllegalStateException"), result)
    }

    @Test
    fun `measureDelay throwing with a secret-shaped message has it redacted`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException("bad uuid 3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f"))

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L) as XrayDataPlaneReadiness.Failed

        assertTrue(result.reason.contains("[redacted]"))
        assertFalse(result.reason.contains("3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f"))
    }

    @Test
    fun `measureDelay exceeding the bounded timeout is Timeout`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayDelayMs = 500L)

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 50L)

        assertEquals(XrayDataPlaneReadiness.Timeout, result)
    }

    @Test
    fun `a negative latency is treated as Failed, never Ready`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayResult = -1L)

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L)

        assertTrue(result is XrayDataPlaneReadiness.Failed)
    }
}
