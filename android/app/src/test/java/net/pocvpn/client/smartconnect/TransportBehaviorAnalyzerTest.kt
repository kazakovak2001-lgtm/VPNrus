package net.pocvpn.client.smartconnect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportBehaviorAnalyzerTest {

    private fun tcp(
        destinationKey: String = "ep1",
        connect: AttemptStageOutcome = AttemptStageOutcome.SUCCEEDED,
        handshake: AttemptStageOutcome = AttemptStageOutcome.SUCCEEDED,
        bytesReceived: Long = 0L,
        progress: TrafficProgressOutcome = TrafficProgressOutcome.NOT_OBSERVED,
        termination: AttemptTermination = AttemptTermination.NONE_OBSERVED,
        observedAtEpochMillis: Long = 0L,
    ) = TransportAttemptObservation(destinationKey, TransportAttemptProtocol.TCP, connect, handshake, 0L, bytesReceived, progress, termination, observedAtEpochMillis)

    private fun udp(
        destinationKey: String = "awg1",
        connect: AttemptStageOutcome = AttemptStageOutcome.FAILED,
        handshake: AttemptStageOutcome = AttemptStageOutcome.FAILED,
        bytesReceived: Long = 0L,
        termination: AttemptTermination = AttemptTermination.NONE_OBSERVED,
        observedAtEpochMillis: Long = 0L,
    ) = TransportAttemptObservation(destinationKey, TransportAttemptProtocol.UDP, connect, handshake, 0L, bytesReceived, TrafficProgressOutcome.NOT_OBSERVED, termination, observedAtEpochMillis)

    @Test
    fun `no observations yields INSUFFICIENT`() {
        val result = TransportBehaviorAnalyzer.assess(emptyList())
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, result.pattern)
        assertEquals(RestrictionEvidenceQuality.INSUFFICIENT, result.quality)
    }

    @Test
    fun `connect failure before any payload, alone, is INSUFFICIENT - a single failed destination is never generalized`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(tcp(connect = AttemptStageOutcome.FAILED, handshake = AttemptStageOutcome.NOT_OBSERVED)))
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, result.pattern)
    }

    @Test
    fun `all connect failed across two distinct destinations yields ALL_CONNECT_FAILED`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(
                tcp(destinationKey = "ep1", connect = AttemptStageOutcome.FAILED, handshake = AttemptStageOutcome.NOT_OBSERVED),
                tcp(destinationKey = "ep2", connect = AttemptStageOutcome.FAILED, handshake = AttemptStageOutcome.NOT_OBSERVED),
            ),
        )
        assertEquals(TransportBehaviorPattern.ALL_CONNECT_FAILED, result.pattern)
        assertTrue(TransportBehaviorSignal.MULTIPLE_DESTINATIONS in result.signals)
    }

    @Test
    fun `handshake failure (connect succeeded, handshake never completed) alone is INSUFFICIENT`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(tcp(connect = AttemptStageOutcome.SUCCEEDED, handshake = AttemptStageOutcome.FAILED)))
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, result.pattern)
    }

    @Test
    fun `successful handshake plus sustained payload yields SUSTAINED_PROGRESS`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(tcp(bytesReceived = 500, progress = TrafficProgressOutcome.SUSTAINED)))
        assertEquals(TransportBehaviorPattern.SUSTAINED_PROGRESS, result.pattern)
    }

    @Test
    fun `two independent sustained-progress observations raise quality to HIGH`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(
                tcp(destinationKey = "ep1", bytesReceived = 500, progress = TrafficProgressOutcome.SUSTAINED),
                tcp(destinationKey = "ep2", bytesReceived = 500, progress = TrafficProgressOutcome.SUSTAINED),
            ),
        )
        assertEquals(TransportBehaviorPattern.SUSTAINED_PROGRESS, result.pattern)
        assertEquals(RestrictionEvidenceQuality.HIGH, result.quality)
    }

    @Test
    fun `early payload stall (handshake+payload then stall, no reset) yields EARLY_DROP at LOW confidence when observed once`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(tcp(bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD)))
        assertEquals(TransportBehaviorPattern.EARLY_DROP, result.pattern)
        assertEquals(RestrictionEvidenceQuality.LOW, result.quality)
    }

    @Test
    fun `repeated early-drop stalls to the SAME destination yield REPEATED_EARLY_DROP at HIGH confidence`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(
                tcp(destinationKey = "ep1", bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, observedAtEpochMillis = 0L),
                tcp(destinationKey = "ep1", bytesReceived = 200, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, observedAtEpochMillis = 1L),
            ),
        )
        assertEquals(TransportBehaviorPattern.REPEATED_EARLY_DROP, result.pattern)
        assertEquals(RestrictionEvidenceQuality.HIGH, result.quality)
    }

    @Test
    fun `early-drop stalls across TWO DISTINCT destinations yield the multi-destination pattern, still HIGH`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(
                tcp(destinationKey = "ep1", bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD),
                tcp(destinationKey = "ep2", bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD),
            ),
        )
        assertEquals(TransportBehaviorPattern.REPEATED_EARLY_DROP_MULTI_DESTINATION, result.pattern)
        assertEquals(RestrictionEvidenceQuality.HIGH, result.quality)
    }

    @Test
    fun `an early-drop stall reset by the peer (RST) is never classified as early-drop at all`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(tcp(bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, termination = AttemptTermination.RST)),
        )
        assertTrue(result.pattern != TransportBehaviorPattern.EARLY_DROP)
        assertTrue(result.pattern != TransportBehaviorPattern.REPEATED_EARLY_DROP)
    }

    @Test
    fun `an early timeout with no protocol progress at all is not EARLY_DROP - no payload phase was ever entered`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(tcp(connect = AttemptStageOutcome.SUCCEEDED, handshake = AttemptStageOutcome.SUCCEEDED, bytesReceived = 0L, termination = AttemptTermination.TIMEOUT)),
        )
        assertTrue(result.pattern != TransportBehaviorPattern.EARLY_DROP)
    }

    @Test
    fun `a stall on one destination while another sustains progress is contradictory and INSUFFICIENT - never generalized`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(
                tcp(destinationKey = "ep1", bytesReceived = 100, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD),
                tcp(destinationKey = "ep2", bytesReceived = 500, progress = TrafficProgressOutcome.SUSTAINED),
            ),
        )
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, result.pattern)
        assertTrue(TransportBehaviorSignal.CONTRADICTORY in result.signals)
    }

    @Test
    fun `UDP no-response while TCP works yields UDP_NO_RESPONSE_TCP_OK`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(udp(), tcp(handshake = AttemptStageOutcome.SUCCEEDED)))
        assertEquals(TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK, result.pattern)
        assertTrue(TransportBehaviorSignal.UDP_NO_RESPONSE in result.signals)
    }

    @Test
    fun `a UDP response is never treated as no-response, even alongside a working TCP flow`() {
        val result = TransportBehaviorAnalyzer.assess(
            listOf(udp(connect = AttemptStageOutcome.SUCCEEDED, handshake = AttemptStageOutcome.SUCCEEDED, bytesReceived = 10L), tcp(handshake = AttemptStageOutcome.SUCCEEDED)),
        )
        assertTrue(result.pattern != TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK)
        assertTrue(TransportBehaviorSignal.UDP_RESPONSE in result.signals)
    }

    @Test
    fun `UDP no-response WITHOUT any working TCP evidence is never claimed as UDP-specific filtering`() {
        val result = TransportBehaviorAnalyzer.assess(listOf(udp()))
        assertTrue(result.pattern != TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK)
    }

    @Test
    fun `stale observations are excluded and never influence the assessment`() {
        val fresh = tcp(bytesReceived = 500, progress = TrafficProgressOutcome.SUSTAINED, observedAtEpochMillis = 1_000_000L)
        val stale = tcp(destinationKey = "ep2", connect = AttemptStageOutcome.FAILED, handshake = AttemptStageOutcome.NOT_OBSERVED, observedAtEpochMillis = 0L)
        val result = TransportBehaviorAnalyzer.assess(listOf(fresh, stale), nowEpochMillis = 1_000_000L, staleAfterMillis = 100L)
        assertEquals(TransportBehaviorPattern.SUSTAINED_PROGRESS, result.pattern)
        assertEquals(1, result.observationCount)
    }

}
