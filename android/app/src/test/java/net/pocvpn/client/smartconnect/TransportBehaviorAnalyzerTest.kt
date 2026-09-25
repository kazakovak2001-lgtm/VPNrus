package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL1 - behavioral network classification: the six required classifier
 * scenarios (normal, UDP blocked, early drop, repeated early drop, hard
 * block, ambiguous) driven through the real RestrictionClassifier, plus the
 * analyzer's own no-byte-threshold, staleness, contradiction and privacy
 * guarantees.
 */
class TransportBehaviorAnalyzerTest {

    private fun profile(validatedInternet: Boolean = true) = NetworkProfile(
        type = NetworkType.CELLULAR, validatedInternet = validatedInternet, metered = true, roaming = false,
        captivePortal = false, ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
    )

    private fun evidence(
        observations: List<TransportAttemptObservation>,
        validatedInternet: Boolean = true,
        diverseInternetReachable: Boolean? = null,
    ) = RestrictionEvidence(
        networkProfile = profile(validatedInternet),
        transportState = TransportState.Disconnected,
        awgHandshakeFresh = null,
        gatewayHttpsReachable = null,
        diverseInternetReachable = diverseInternetReachable,
        transportObservations = observations,
    )

    private fun tcp(
        destination: String = "path-a",
        connect: AttemptStageOutcome = AttemptStageOutcome.SUCCEEDED,
        handshake: AttemptStageOutcome = AttemptStageOutcome.SUCCEEDED,
        bytesReceived: Long = 4_096,
        progress: TrafficProgressOutcome = TrafficProgressOutcome.SUSTAINED,
        termination: AttemptTermination = AttemptTermination.NONE_OBSERVED,
        at: Long = 1_000L,
    ) = TransportAttemptObservation(destination, TransportAttemptProtocol.TCP, connect, handshake, 2_048, bytesReceived, progress, termination, at)

    private fun udpNoResponse(destination: String = "path-awg", at: Long = 1_000L) = TransportAttemptObservation(
        destination, TransportAttemptProtocol.UDP, AttemptStageOutcome.SUCCEEDED, AttemptStageOutcome.FAILED,
        bytesSent = 148, bytesReceived = 0, progress = TrafficProgressOutcome.NO_PAYLOAD, termination = AttemptTermination.TIMEOUT, observedAtEpochMillis = at,
    )

    private fun earlyDrop(destination: String = "path-a", bytesReceived: Long = 9_000, termination: AttemptTermination = AttemptTermination.TIMEOUT, at: Long = 1_000L) =
        tcp(destination = destination, bytesReceived = bytesReceived, progress = TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, termination = termination, at = at)

    private fun connectFailed(destination: String) = tcp(
        destination = destination, connect = AttemptStageOutcome.FAILED, handshake = AttemptStageOutcome.NOT_OBSERVED,
        bytesReceived = 0, progress = TrafficProgressOutcome.NO_PAYLOAD, termination = AttemptTermination.TIMEOUT,
    )

    // --- The six required scenarios, end-to-end through RestrictionClassifier ---

    @Test
    fun `test 1 normal TCP - connect, TLS, payload, continuous progress - NORMAL (NO_RESTRICTION_OBSERVED)`() {
        val assessment = RestrictionClassifier.assess(evidence(listOf(tcp())))
        assertEquals(RestrictionClass.NO_RESTRICTION_OBSERVED, assessment.classification)
        assertEquals(TransportBehaviorPattern.SUSTAINED_PROGRESS, assessment.transportBehavior?.pattern)
        assertTrue(RestrictionEvidenceReason.TRANSPORT_SUSTAINED_PROGRESS in assessment.reasons)
        assertTrue(TransportBehaviorSignal.STREAM_PROGRESS in assessment.transportBehavior!!.signals)
    }

    @Test
    fun `test 2 UDP blocked - no UDP response while TCP works - POSSIBLE_UDP_OR_AWG_FILTERING`() {
        val assessment = RestrictionClassifier.assess(evidence(listOf(udpNoResponse(), tcp(destination = "path-reality"))))
        assertEquals(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, assessment.classification)
        assertEquals(TransportBehaviorPattern.UDP_NO_RESPONSE_TCP_OK, assessment.transportBehavior?.pattern)
        assertTrue(TransportBehaviorSignal.UDP_NO_RESPONSE in assessment.transportBehavior!!.signals)
        assertEquals(RestrictionEvidenceQuality.LOW, assessment.evidenceQuality)
    }

    @Test
    fun `test 3 early drop - TCP+TLS+initial payload then stall, no RST, timeout - POSSIBLE_EARLY_DROP with LOW confidence`() {
        val assessment = RestrictionClassifier.assess(evidence(listOf(earlyDrop())))
        assertEquals(RestrictionClass.POSSIBLE_EARLY_DROP, assessment.classification)
        assertEquals(RestrictionEvidenceQuality.LOW, assessment.evidenceQuality)
        val signals = assessment.transportBehavior!!.signals
        listOf(
            TransportBehaviorSignal.TCP_CONNECT, TransportBehaviorSignal.TLS_HANDSHAKE, TransportBehaviorSignal.INITIAL_PAYLOAD,
            TransportBehaviorSignal.STALL, TransportBehaviorSignal.TIMEOUT,
        ).forEach { assertTrue("missing $it", it in signals) }
        assertFalse(TransportBehaviorSignal.RST in signals)
    }

    @Test
    fun `test 4a repeated early drop on one destination - POSSIBLE_EARLY_DROP with HIGH confidence`() {
        val assessment = RestrictionClassifier.assess(evidence(listOf(earlyDrop(at = 1_000), earlyDrop(at = 2_000), earlyDrop(at = 3_000))))
        assertEquals(RestrictionClass.POSSIBLE_EARLY_DROP, assessment.classification)
        assertEquals(RestrictionEvidenceQuality.HIGH, assessment.evidenceQuality)
        assertTrue(TransportBehaviorSignal.REPEATED_FAILURE in assessment.transportBehavior!!.signals)
        assertTrue(RestrictionEvidenceReason.TRANSPORT_REPEATED_EARLY_DROP in assessment.reasons)
    }

    @Test
    fun `test 4b repeated early drop across distinct destinations - POSSIBLE_HARD_WHITELIST`() {
        val assessment = RestrictionClassifier.assess(evidence(listOf(earlyDrop("path-a"), earlyDrop("path-b"))))
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, assessment.classification)
        assertEquals(RestrictionEvidenceQuality.HIGH, assessment.evidenceQuality)
        assertTrue(TransportBehaviorSignal.MULTIPLE_DESTINATIONS in assessment.transportBehavior!!.signals)
    }

    @Test
    fun `test 5 hard block - TCP cannot connect anywhere, OS cannot validate - POSSIBLE_FULL_SHUTDOWN`() {
        val assessment = RestrictionClassifier.assess(
            evidence(listOf(connectFailed("path-a"), connectFailed("path-b"), udpNoResponse("path-c")), validatedInternet = false),
        )
        assertEquals(RestrictionClass.POSSIBLE_FULL_SHUTDOWN, assessment.classification)
        assertEquals(TransportBehaviorPattern.ALL_CONNECT_FAILED, assessment.transportBehavior?.pattern)
        assertTrue(TransportBehaviorSignal.TCP_CONNECT_FAILED in assessment.transportBehavior!!.signals)
    }

    @Test
    fun `test 5b the same total connect failure with validated internet and failing diverse probes is POSSIBLE_HARD_WHITELIST, not shutdown`() {
        val result = RestrictionClassifier.classify(
            evidence(listOf(connectFailed("path-a"), connectFailed("path-b")), validatedInternet = true, diverseInternetReachable = false),
        )
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, result)
    }

    @Test
    fun `test 6 ambiguous - a single connect with no progress data - UNKNOWN with INSUFFICIENT quality`() {
        val lonely = tcp(bytesReceived = 0, progress = TrafficProgressOutcome.NOT_OBSERVED)
        val assessment = RestrictionClassifier.assess(evidence(listOf(lonely)))
        assertEquals(RestrictionClass.UNKNOWN, assessment.classification)
        assertEquals(RestrictionEvidenceQuality.INSUFFICIENT, assessment.evidenceQuality)
    }

    @Test
    fun `a single hard connect failure is not enough for FULL_SHUTDOWN - falls back to INTERNET_NOT_VALIDATED`() {
        val result = RestrictionClassifier.classify(evidence(listOf(connectFailed("path-a")), validatedInternet = false))
        assertEquals(RestrictionClass.INTERNET_NOT_VALIDATED, result)
    }

    // --- Analyzer guarantees ---

    @Test
    fun `early-drop detection is behavioral - identical at 1 KB, exactly 16384 bytes and 1 MB`() {
        listOf(1_024L, 16_384L, 16_385L, 1_048_576L).forEach { bytes ->
            val assessment = TransportBehaviorAnalyzer.assess(listOf(earlyDrop(bytesReceived = bytes)))
            assertEquals("bytesReceived=$bytes", TransportBehaviorPattern.EARLY_DROP, assessment.pattern)
        }
    }

    @Test
    fun `a stall that ends in a peer RST is not the silent early-drop pattern`() {
        val assessment = TransportBehaviorAnalyzer.assess(listOf(earlyDrop(termination = AttemptTermination.RST)))
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, assessment.pattern)
        assertTrue(TransportBehaviorSignal.RST in assessment.signals)
    }

    @Test
    fun `sustained progress exactly 16384 bytes in is never flagged - the byte count alone means nothing`() {
        val assessment = TransportBehaviorAnalyzer.assess(listOf(tcp(bytesReceived = 16_384)))
        assertEquals(TransportBehaviorPattern.SUSTAINED_PROGRESS, assessment.pattern)
    }

    @Test
    fun `an early drop on one path while another TCP path progresses is contradictory and never generalized`() {
        val assessment = TransportBehaviorAnalyzer.assess(listOf(earlyDrop("path-a"), tcp(destination = "path-b")))
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, assessment.pattern)
        assertTrue(TransportBehaviorSignal.CONTRADICTORY in assessment.signals)
        assertEquals(RestrictionClass.UNKNOWN, RestrictionClassifier.classify(evidence(listOf(earlyDrop("path-a"), tcp(destination = "path-b")))))
    }

    @Test
    fun `stale observations lose their influence entirely`() {
        val now = 10_000_000L
        val stale = earlyDrop(at = now - RestrictionClassifier.DEFAULT_STALE_AFTER_MILLIS - 1)
        val assessment = TransportBehaviorAnalyzer.assess(listOf(stale), nowEpochMillis = now)
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, assessment.pattern)
        assertEquals(0, assessment.observationCount)
        assertEquals(RestrictionClass.UNKNOWN, RestrictionClassifier.classify(evidence(listOf(stale)), nowEpochMillis = now))
    }

    @Test
    fun `future-dated observations (clock skew) are never trusted`() {
        val assessment = TransportBehaviorAnalyzer.assess(listOf(earlyDrop(at = 5_000)), nowEpochMillis = 1_000)
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, assessment.pattern)
    }

    @Test
    fun `no observations leaves RestrictionClassifier byte-for-byte unchanged`() {
        val noBehavior = RestrictionEvidence(profile(), TransportState.Disconnected, awgHandshakeFresh = false, gatewayHttpsReachable = true, diverseInternetReachable = null)
        assertEquals(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, RestrictionClassifier.classify(noBehavior))
        assertNull(RestrictionClassifier.assess(noBehavior).transportBehavior)
    }

    @Test
    fun `a fresh AWG handshake still outranks any behavior evidence`() {
        val e = evidence(listOf(earlyDrop())).copy(awgHandshakeFresh = true)
        assertEquals(RestrictionClass.NO_RESTRICTION_OBSERVED, RestrictionClassifier.classify(e))
    }

    @Test
    fun `the enum still never claims DPI, TSPU or a confirmed whitelist - new classes stay POSSIBLE_`() {
        val names = RestrictionClass.entries.map { it.name }
        assertTrue("POSSIBLE_EARLY_DROP" in names)
        assertTrue("POSSIBLE_FULL_SHUTDOWN" in names)
        listOf("EARLY_DROP", "FULL_SHUTDOWN", "WHITELIST", "DPI_BLOCKED").forEach { assertFalse(it in names) }
    }

    @Test
    fun `TransportAttemptObservation carries only the closed, non-secret field set`() {
        val fieldNames = TransportAttemptObservation::class.java.declaredFields.map { it.name }.filterNot { it.contains('$') }.toSet()
        assertEquals(
            setOf(
                "destinationKey", "protocol", "connect", "handshake", "bytesSent", "bytesReceived",
                "progress", "termination", "observedAtEpochMillis",
            ),
            fieldNames,
        )
    }
}
