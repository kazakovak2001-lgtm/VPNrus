package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B-WL7 - post-connect traffic-progress verification: connect/handshake alone never counts as working. */
class TrafficProgressMonitorTest {

    private val policy = TrafficProgressPolicy(verificationWindowMillis = 10_000, stallWindowMillis = 20_000)

    private fun s(t: Long, rx: Long, tx: Long) = TrafficProgressSample(t, rx, tx)

    @Test
    fun `no samples yet - VERIFYING, never assumed healthy`() {
        assertEquals(TrafficProgressVerdict.VERIFYING, TrafficProgressMonitor.evaluate(emptyList(), policy))
        assertFalse(TrafficProgressMonitor.isUnhealthy(TrafficProgressVerdict.VERIFYING))
    }

    @Test
    fun `receive progress advancing across the verification window - VERIFIED and maps to SUSTAINED`() {
        val v = TrafficProgressMonitor.evaluate(listOf(s(0, 0, 500), s(4_000, 20_000, 3_000), s(8_000, 90_000, 6_000), s(12_000, 400_000, 9_000)), policy)
        assertEquals(TrafficProgressVerdict.VERIFIED, v)
        assertEquals(TrafficProgressOutcome.SUSTAINED, TrafficProgressMonitor.toProgressOutcome(v))
    }

    @Test
    fun `progress that has not yet spanned the verification window stays VERIFYING`() {
        assertEquals(TrafficProgressVerdict.VERIFYING, TrafficProgressMonitor.evaluate(listOf(s(0, 0, 100), s(2_000, 500, 200), s(4_000, 900, 300)), policy))
    }

    @Test
    fun `initial payload, then silence while we keep sending for the stall window - STALLED_AFTER_INITIAL_PAYLOAD (UNHEALTHY)`() {
        val v = TrafficProgressMonitor.evaluate(
            listOf(s(0, 0, 600), s(2_000, 14_000, 2_000), s(10_000, 14_000, 8_000), s(22_000, 14_000, 15_000)),
            policy,
        )
        assertEquals(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, v)
        assertTrue(TrafficProgressMonitor.isUnhealthy(v))
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, TrafficProgressMonitor.toProgressOutcome(v))
    }

    @Test
    fun `the stall verdict does not depend on how many bytes arrived before it`() {
        listOf(512L, 16_384L, 2_000_000L).forEach { initial ->
            val v = TrafficProgressMonitor.evaluate(listOf(s(0, 0, 100), s(1_000, initial, 400), s(25_000, initial, 9_000)), policy)
            assertEquals("initial=$initial", TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, v)
        }
    }

    @Test
    fun `we send, the peer never answers within the stall window - NO_PAYLOAD (UNHEALTHY)`() {
        val v = TrafficProgressMonitor.evaluate(listOf(s(0, 0, 100), s(10_000, 0, 3_000), s(20_000, 0, 6_000)), policy)
        assertEquals(TrafficProgressVerdict.NO_PAYLOAD, v)
        assertTrue(TrafficProgressMonitor.isUnhealthy(v))
    }

    @Test
    fun `silence with no outbound demand is IDLE, never a fault`() {
        val v = TrafficProgressMonitor.evaluate(listOf(s(0, 50_000, 4_000), s(15_000, 50_000, 4_000), s(30_000, 50_000, 4_000)), policy)
        assertEquals(TrafficProgressVerdict.IDLE, v)
        assertFalse(TrafficProgressMonitor.isUnhealthy(v))
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, TrafficProgressMonitor.toProgressOutcome(v))
    }

    @Test
    fun `a verified session that later goes idle is not reported as stalled`() {
        val v = TrafficProgressMonitor.evaluate(
            listOf(s(0, 0, 100), s(3_000, 9_000, 900), s(11_000, 70_000, 2_000), s(40_000, 70_000, 2_000)),
            policy,
        )
        assertEquals(TrafficProgressVerdict.IDLE, v)
    }

    @Test
    fun `counters going backwards (reset, different session) - UNAVAILABLE, no conclusion`() {
        assertEquals(TrafficProgressVerdict.UNAVAILABLE, TrafficProgressMonitor.evaluate(listOf(s(0, 5_000, 100), s(1_000, 10, 200)), policy))
    }

    @Test
    fun `samples come only from real counters - unsupported stats yield no sample`() {
        assertNull(TrafficProgressSample.fromCounters(TransportStats.Unsupported, 0))
        assertNull(TrafficProgressSample.fromCounters(TransportStats.Unavailable, 0))
        assertEquals(s(7, 10, 20), TrafficProgressSample.fromCounters(TransportStats.Counters(10, 20, null), 7))
    }

    @Test
    fun `a stalled session feeds the B-WL1 classifier as an early drop`() {
        val v = TrafficProgressMonitor.evaluate(listOf(s(0, 0, 600), s(2_000, 14_000, 2_000), s(22_000, 14_000, 15_000)), policy)
        val observation = TransportAttemptObservation(
            destinationKey = "opaque-path", protocol = TransportAttemptProtocol.TCP,
            connect = AttemptStageOutcome.SUCCEEDED, handshake = AttemptStageOutcome.SUCCEEDED,
            bytesSent = 15_000, bytesReceived = 14_000, progress = TrafficProgressMonitor.toProgressOutcome(v),
            termination = AttemptTermination.TIMEOUT, observedAtEpochMillis = 1L,
        )
        assertEquals(TransportBehaviorPattern.EARLY_DROP, TransportBehaviorAnalyzer.assess(listOf(observation)).pattern)
    }
}
