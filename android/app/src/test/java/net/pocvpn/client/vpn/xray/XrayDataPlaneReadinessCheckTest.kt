package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
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
    fun `measureDelay throwing is Failed with the exception's class name`() = runBlocking {
        val runtime = FakeXrayCoreRuntime(measureDelayThrows = IllegalStateException("dial failed"))

        val result = XrayDataPlaneReadinessCheck.check(runtime, timeoutMs = 1_000L)

        assertEquals(XrayDataPlaneReadiness.Failed("IllegalStateException"), result)
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
