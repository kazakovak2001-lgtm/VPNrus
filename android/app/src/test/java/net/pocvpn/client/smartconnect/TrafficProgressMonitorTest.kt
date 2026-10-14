package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertNotNull
import org.junit.Test

class TrafficProgressMonitorTest {

    private val policy = TrafficProgressPolicy(verificationWindowMillis = 1_000L, stallWindowMillis = 2_000L)

    private fun sample(elapsedMillis: Long, rx: Long, tx: Long) = TrafficProgressSample(elapsedMillis, rx, tx)

    @Test
    fun `no samples yields VERIFYING`() {
        assertEquals(TrafficProgressVerdict.VERIFYING, TrafficProgressMonitor.evaluate(emptyList(), policy))
    }

    @Test
    fun `repeated receive advances across the verification window with no stall yields VERIFIED`() {
        val samples = listOf(sample(0, 0, 0), sample(400, 100, 50), sample(900, 300, 100), sample(1200, 600, 150))
        assertEquals(TrafficProgressVerdict.VERIFIED, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `sending with no reply at all for the whole stall window yields NO_PAYLOAD - never a byte-count rule`() {
        val samples = listOf(sample(0, 0, 0), sample(2100, 0, 500))
        assertEquals(TrafficProgressVerdict.NO_PAYLOAD, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `some payload then silence for the whole stall window while still sending yields STALLED_AFTER_INITIAL_PAYLOAD`() {
        val samples = listOf(sample(0, 0, 0), sample(200, 50, 50), sample(2300, 50, 600))
        assertEquals(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `a single byte of payload is treated exactly the same shape as a large payload - no magic threshold`() {
        val tiny = listOf(sample(0, 0, 0), sample(2300, 1, 600))
        val large = listOf(sample(0, 0, 0), sample(2300, 1_000_000, 600))
        assertEquals(TrafficProgressMonitor.evaluate(tiny, policy), TrafficProgressMonitor.evaluate(large, policy))
    }

    @Test
    fun `silence with no outbound demand either is IDLE, never treated as a fault`() {
        val samples = listOf(sample(0, 0, 0), sample(2300, 0, 0))
        assertEquals(TrafficProgressVerdict.IDLE, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `counters going backwards is UNAVAILABLE, never a conclusion`() {
        val samples = listOf(sample(0, 500, 0), sample(1000, 100, 0))
        assertEquals(TrafficProgressVerdict.UNAVAILABLE, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `not enough time has passed yet stays VERIFYING, never promoted to healthy by default`() {
        val samples = listOf(sample(0, 0, 0), sample(100, 50, 20))
        assertEquals(TrafficProgressVerdict.VERIFYING, TrafficProgressMonitor.evaluate(samples, policy))
    }

    @Test
    fun `only a stall or no-payload verdict is unhealthy`() {
        assertEquals(true, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD))
        assertEquals(true, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.NO_PAYLOAD))
        assertEquals(false, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.VERIFIED))
        assertEquals(false, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.IDLE))
        assertEquals(false, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.VERIFYING))
        assertEquals(false, TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.UNAVAILABLE))
    }

    @Test
    fun `verdict maps onto the B-WL1 observation vocabulary without ever claiming progress from a non-conclusive verdict`() {
        assertEquals(TrafficProgressOutcome.SUSTAINED, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.VERIFIED))
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD))
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.NO_PAYLOAD))
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.VERIFYING))
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.IDLE))
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, TrafficProgressMonitor.toProgressOutcome(TrafficProgressVerdict.UNAVAILABLE))
    }

    @Test
    fun `fromCounters reads real Counters stats, and is null for every non-counter stats value`() {
        val counters = TransportStats.Counters(bytesReceived = 100, bytesSent = 50, lastHandshakeEpochMillis = 5L)
        val sample = TrafficProgressSample.fromCounters(counters, elapsedMillis = 10L)
        assertNotNull(sample)
        assertEquals(100L, sample!!.bytesReceived)
        assertEquals(50L, sample.bytesSent)
        assertNull(TrafficProgressSample.fromCounters(TransportStats.Unsupported, 10L))
        assertNull(TrafficProgressSample.fromCounters(TransportStats.Unavailable, 10L))
        assertNull(TrafficProgressSample.fromCounters(TransportStats.NotImplemented, 10L))
    }

    @Test
    fun `constructing a policy with a non-positive window is rejected`() {
        var threw = false
        try {
            TrafficProgressPolicy(verificationWindowMillis = 0L)
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertEquals(true, threw)
    }

    // P2 (M1 mitigation) - per-transport stall window.

    @Test
    fun `Xray family transports get the 65s stall window`() {
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP, TransportKind.XRAY_XHTTP)) {
            assertEquals(kind.name, 65_000L, TrafficProgressPolicy.forTransport(kind).stallWindowMillis)
        }
    }

    @Test
    fun `AWG and every other transport keep the 20s stall window`() {
        for (kind in TransportKind.values().filterNot { it == TransportKind.XRAY_REALITY || it == TransportKind.TLS_TCP || it == TransportKind.XRAY_XHTTP }) {
            assertEquals(kind.name, 20_000L, TrafficProgressPolicy.forTransport(kind).stallWindowMillis)
        }
        assertEquals(TrafficProgressPolicy(), TrafficProgressPolicy.forTransport(TransportKind.AMNEZIA_WG))
    }

    @Test
    fun `verification window stays 10s for every transport`() {
        for (kind in TransportKind.values()) {
            assertEquals(kind.name, 10_000L, TrafficProgressPolicy.forTransport(kind).verificationWindowMillis)
        }
    }

    @Test
    fun `Xray uplink-only past 20s but under 65s is not yet a stall, AWG with the same samples is`() {
        val samples = listOf(sample(0, 0, 0), sample(30_000, 0, 9_000), sample(64_500, 0, 18_000))
        assertEquals(TrafficProgressVerdict.VERIFYING, TrafficProgressMonitor.evaluate(samples, TrafficProgressPolicy.forTransport(TransportKind.XRAY_REALITY)))
        assertEquals(TrafficProgressVerdict.NO_PAYLOAD, TrafficProgressMonitor.evaluate(samples, TrafficProgressPolicy.forTransport(TransportKind.AMNEZIA_WG)))
    }

    @Test
    fun `Xray stall logic still applies once the 65s window is exceeded`() {
        val xray = TrafficProgressPolicy.forTransport(TransportKind.XRAY_XHTTP)
        val noPayload = listOf(sample(0, 0, 0), sample(65_000, 0, 18_000))
        val stalled = listOf(sample(0, 0, 0), sample(500, 512, 300), sample(65_500, 512, 18_000))
        assertEquals(TrafficProgressVerdict.NO_PAYLOAD, TrafficProgressMonitor.evaluate(noPayload, xray))
        assertEquals(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, TrafficProgressMonitor.evaluate(stalled, xray))
    }
}
