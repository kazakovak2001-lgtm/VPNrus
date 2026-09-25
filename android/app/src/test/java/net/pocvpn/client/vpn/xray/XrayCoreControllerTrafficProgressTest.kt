@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import android.content.Context
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.smartconnect.TrafficProgressSnapshot
import net.pocvpn.client.smartconnect.TrafficProgressVerdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B-WL-R3/R4 - the B33 session watchdog extended with Xray outbound counters:
 * counters feed TrafficProgressMonitor, a stall only TRIGGERS the existing
 * Xray-native confirmation round trip, and teardown still needs two
 * consecutive failed round trips. A runtime without counters changes nothing.
 */
class XrayCoreControllerTrafficProgressTest {

    private val profile = XrayProfile(
        server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    private class CountingRuntime(private val hasCounters: Boolean) : XrayCoreRuntime {
        var stopLoopCallCount = 0
            private set
        var measureDelayCallCount = 0
            private set
        private var started = 0
        val statsQueue = ArrayDeque<String>()
        val measureResults = ArrayDeque<Boolean>()

        override fun ensureCoreEnvInitialized(context: Context) {}
        override val isRunning: Boolean get() = started > stopLoopCallCount
        override fun startLoop(configContent: String, tunFd: Int) { started++ }
        override fun stopLoop() { stopLoopCallCount++ }
        override fun measureDelay(url: String): Long {
            measureDelayCallCount++
            val ok = if (measureResults.isEmpty()) true else measureResults.removeFirst()
            if (!ok) throw java.io.IOException("simulated failed round trip")
            return 1L
        }
        // "" = counter channel present, nothing moved since the last query.
        override fun queryOutboundTrafficStats(): String? = if (!hasCounters) null else (statsQueue.removeFirstOrNull() ?: "")
    }

    private fun controller(runtime: XrayCoreRuntime, scope: kotlinx.coroutines.CoroutineScope): XrayCoreController {
        val repository = SecureXrayProfileRepository(FileXrayProfileStore(Files.createTempDirectory("traffic-progress").toFile()), FakeAesGcmKeyEncryptor())
        kotlinx.coroutines.runBlocking { repository.saveProfile(profile) }
        return XrayCoreController(repository, runtime, "net.pocvpn.client.test", {}, { 42 }, {}, probeScope = scope)
    }

    private fun tick(scope: kotlinx.coroutines.test.TestScope, times: Int = 1) = repeat(times) {
        scope.advanceTimeBy(XRAY_SAMPLE_INTERVAL_MS)
        scope.runCurrent()
    }

    @Test
    fun `Direct session on a runtime without counters starts no watchdog - identical to before`() = runTest {
        val runtime = CountingRuntime(hasCounters = false)
        val reports = mutableListOf<TrafficProgressSnapshot>()
        assertEquals(XrayCoreStartOutcome.Started, controller(runtime, this).requestStart(onTrafficProgress = { reports += it }))
        tick(this, 12)
        assertEquals("only the pre-Started confirmation", 1, runtime.measureDelayCallCount)
        assertTrue(reports.isEmpty())
        // runTest completing here also proves no watchdog coroutine was left running.
    }

    @Test
    fun `Direct session with steady two-way progress is VERIFIED and triggers no extra round trip`() = runTest {
        val runtime = CountingRuntime(hasCounters = true)
        repeat(6) { runtime.statsQueue.addLast("nova-vless-reality-out,uplink,800;nova-vless-reality-out,downlink,40000;") }
        val reports = mutableListOf<TrafficProgressSnapshot>()
        val c = controller(runtime, this)
        c.requestStart(onTrafficProgress = { reports += it })
        tick(this, 4)
        assertEquals(TrafficProgressVerdict.VERIFIED, reports.last().verdict)
        assertEquals(1, runtime.measureDelayCallCount)
        assertEquals(0, runtime.stopLoopCallCount)
        assertTrue(reports.last().rxBytes > 0 && reports.last().txBytes > 0)
        c.requestStop()
    }

    @Test
    fun `Direct session with no traffic at all is IDLE - never a fault, never a probe`() = runTest {
        val runtime = CountingRuntime(hasCounters = true)
        val reports = mutableListOf<TrafficProgressSnapshot>()
        val c = controller(runtime, this)
        c.requestStart(onTrafficProgress = { reports += it })
        tick(this, 6)
        assertEquals(TrafficProgressVerdict.IDLE, reports.last().verdict)
        assertEquals(1, runtime.measureDelayCallCount)
        c.requestStop()
    }

    @Test
    fun `early-drop shape - payload then silence while sending - triggers a confirmation round trip, a successful one keeps the session`() = runTest {
        val runtime = CountingRuntime(hasCounters = true)
        runtime.statsQueue.addLast("out,downlink,9000;out,uplink,600;")
        repeat(5) { runtime.statsQueue.addLast("out,uplink,700;") }
        val reports = mutableListOf<TrafficProgressSnapshot>()
        var unhealthy = 0
        val c = controller(runtime, this)
        c.requestStart(onRelayHealthLost = { unhealthy++ }, onTrafficProgress = { reports += it })
        tick(this, 5)
        assertTrue(reports.any { it.verdict == TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD })
        assertEquals("stall triggered exactly one extra round trip", 2, runtime.measureDelayCallCount)
        assertEquals(0, runtime.stopLoopCallCount)
        assertEquals(0, unhealthy)
        c.requestStop()
    }

    @Test
    fun `a persistent stall with two failed confirmation round trips tears the Direct session down through the B33 path`() = runTest {
        val runtime = CountingRuntime(hasCounters = true)
        runtime.measureResults.addLast(true) // pre-Started confirmation
        runtime.measureResults.addLast(false)
        runtime.measureResults.addLast(false)
        runtime.statsQueue.addLast("out,downlink,9000;out,uplink,600;")
        repeat(10) { runtime.statsQueue.addLast("out,uplink,700;") }
        var unhealthy = 0
        val c = controller(runtime, this)
        c.requestStart(onRelayHealthLost = { unhealthy++ })
        tick(this, 7)
        assertEquals(1, runtime.stopLoopCallCount)
        assertEquals(1, unhealthy)
    }

    @Test
    fun `Relayed session keeps its B33 periodic probe cadence while also reporting progress`() = runTest {
        val runtime = CountingRuntime(hasCounters = true)
        val reports = mutableListOf<TrafficProgressSnapshot>()
        val c = controller(runtime, this)
        c.requestStart(confirmationContext = RemoteConfirmationContext.Relayed("152.70.43.1"), onTrafficProgress = { reports += it })
        advanceTimeBy(40_000L); runCurrent()
        assertEquals("confirmation + probes at 20 s and 40 s", 3, runtime.measureDelayCallCount)
        assertTrue(reports.isNotEmpty())
        c.requestStop()
    }

    private companion object {
        const val XRAY_SAMPLE_INTERVAL_MS = 5_000L
    }
}
