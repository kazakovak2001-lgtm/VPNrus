package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B-WL-R1/R2 - observation store, the observation factory, and the reference-probe contrast. */
class TransportObservationRuntimeTest {

    private fun tcp(key: String) = TransportAttemptObservations.tcpConfirmed(key, TransportStats.Unsupported, 1L)

    // --- TransportObservationStore ---

    @Test
    fun `store is network-scoped - one network never sees another network's evidence`() {
        val store = TransportObservationStore()
        store.record("net-mobile", tcp("a"))
        store.record("net-wifi", tcp("b"))
        assertEquals(listOf("a"), store.recent("net-mobile").map { it.destinationKey })
        assertEquals(listOf("b"), store.recent("net-wifi").map { it.destinationKey })
        assertTrue(store.recent("net-other").isEmpty())
    }

    @Test
    fun `store is bounded - oldest evicted first`() {
        val store = TransportObservationStore(capacity = 3)
        (1..5).forEach { store.record("n", tcp("k$it")) }
        assertEquals(listOf("k3", "k4", "k5"), store.recent("n").map { it.destinationKey })
        store.clear()
        assertTrue(store.recent("n").isEmpty())
    }

    // --- TransportAttemptObservations: the required observation cases ---

    @Test
    fun `successful TCP - connect and handshake succeeded, no progress claim yet`() {
        val o = TransportAttemptObservations.tcpConfirmed("p", TransportStats.Unsupported, 5L)
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.connect)
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.handshake)
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, o.progress)
        assertEquals(0L, o.bytesReceived) // no counters -> 0, never invented
    }

    @Test
    fun `unconfirmed TCP - stages the runtime cannot see stay NOT_OBSERVED and never drive a classification`() {
        val o = TransportAttemptObservations.tcpUnconfirmed("p", 5L)
        assertEquals(AttemptStageOutcome.NOT_OBSERVED, o.connect)
        assertEquals(AttemptStageOutcome.NOT_OBSERVED, o.handshake)
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, TransportBehaviorAnalyzer.assess(listOf(o, o.copy(destinationKey = "q"))).pattern)
    }

    @Test
    fun `UDP no response - handshake failed, zero bytes, timeout`() {
        val o = TransportAttemptObservations.udpHandshake("p", false, TransportStats.Counters(0, 296, null), 5L)
        assertEquals(TransportAttemptProtocol.UDP, o.protocol)
        assertEquals(AttemptStageOutcome.FAILED, o.handshake)
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, o.progress)
        assertEquals(AttemptTermination.TIMEOUT, o.termination)
        assertTrue(TransportBehaviorSignal.UDP_NO_RESPONSE in TransportBehaviorAnalyzer.assess(listOf(o)).signals)
    }

    @Test
    fun `UDP response - bytes came back even though the handshake did not complete, so it is NOT counted as no-response`() {
        val o = TransportAttemptObservations.udpHandshake("p", false, TransportStats.Counters(92, 296, null), 5L)
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, o.progress)
        val signals = TransportBehaviorAnalyzer.assess(listOf(o)).signals
        assertTrue(TransportBehaviorSignal.UDP_RESPONSE in signals)
        assertTrue(TransportBehaviorSignal.UDP_NO_RESPONSE !in signals)
    }

    @Test
    fun `UDP handshake success is a UDP response`() {
        val o = TransportAttemptObservations.udpHandshake("p", true, TransportStats.Unsupported, 5L)
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.handshake)
        assertTrue(TransportBehaviorSignal.UDP_RESPONSE in TransportBehaviorAnalyzer.assess(listOf(o)).signals)
    }

    @Test
    fun `progress verdicts map onto observations - early stall keeps its real byte counts, no-claim verdicts record nothing`() {
        val stalled = TransportAttemptObservations.progress("p", TransportAttemptProtocol.TCP, TrafficProgressSnapshot(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, 9_000, 6_000), 5L)!!
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, stalled.progress)
        assertEquals(9_000L, stalled.bytesReceived)
        assertEquals(AttemptTermination.TIMEOUT, stalled.termination)
        assertEquals(TransportBehaviorPattern.EARLY_DROP, TransportBehaviorAnalyzer.assess(listOf(stalled)).pattern)
        val noPayload = TransportAttemptObservations.progress("p", TransportAttemptProtocol.TCP, TrafficProgressSnapshot(TrafficProgressVerdict.NO_PAYLOAD, 0, 6_000), 5L)!!
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, noPayload.progress)
        listOf(TrafficProgressVerdict.VERIFYING, TrafficProgressVerdict.IDLE, TrafficProgressVerdict.UNAVAILABLE).forEach {
            assertNull(TransportAttemptObservations.progress("p", TransportAttemptProtocol.TCP, TrafficProgressSnapshot(it, 1, 1), 5L))
        }
        val sustained = TransportAttemptObservations.progress("p", TransportAttemptProtocol.TCP, TrafficProgressSnapshot(TrafficProgressVerdict.VERIFIED, 90_000, 6_000), 5L)!!
        assertEquals(TrafficProgressOutcome.SUSTAINED, sustained.progress)
    }

    // --- Classifier: TLS failure, and the reference-probe contrast ---

    private fun evidence(observations: List<TransportAttemptObservation>, validated: Boolean, reference: Boolean?) = RestrictionEvidence(
        NetworkProfile(type = NetworkType.CELLULAR, validatedInternet = validated, metered = true, roaming = false, captivePortal = false,
            ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1),
        TransportState.Disconnected, awgHandshakeFresh = null, gatewayHttpsReachable = null,
        transportObservations = observations, referenceReachable = reference,
    )

    private fun connectFailed(key: String) = TransportAttemptObservation(key, TransportAttemptProtocol.TCP, AttemptStageOutcome.FAILED,
        AttemptStageOutcome.NOT_OBSERVED, 0, 0, TrafficProgressOutcome.NO_PAYLOAD, AttemptTermination.TIMEOUT, 1L)

    @Test
    fun `TLS failure after a successful TCP connect is not a connect failure and alone is insufficient`() {
        val tlsFailed = TransportAttemptObservation("p", TransportAttemptProtocol.TCP, AttemptStageOutcome.SUCCEEDED,
            AttemptStageOutcome.FAILED, 300, 0, TrafficProgressOutcome.NO_PAYLOAD, AttemptTermination.RST, 1L)
        val a = TransportBehaviorAnalyzer.assess(listOf(tlsFailed, tlsFailed.copy(destinationKey = "q")))
        assertEquals(TransportBehaviorPattern.INSUFFICIENT, a.pattern)
        assertTrue(TransportBehaviorSignal.TCP_CONNECT in a.signals)
        assertTrue(TransportBehaviorSignal.RST in a.signals)
    }

    @Test
    fun `every VPN endpoint failing while an allowed reference is reachable is POSSIBLE_HARD_WHITELIST, not a shutdown`() {
        val obs = listOf(connectFailed("a"), connectFailed("b"))
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, RestrictionClassifier.classify(evidence(obs, validated = false, reference = true)))
        assertEquals(RestrictionClass.POSSIBLE_FULL_SHUTDOWN, RestrictionClassifier.classify(evidence(obs, validated = false, reference = false)))
        assertEquals(RestrictionClass.POSSIBLE_FULL_SHUTDOWN, RestrictionClassifier.classify(evidence(obs, validated = false, reference = null)))
    }

    @Test
    fun `a reachable reference alone - no failed attempts - changes nothing`() {
        assertEquals(RestrictionClass.UNKNOWN, RestrictionClassifier.classify(evidence(emptyList(), validated = true, reference = true)))
    }

    @Test
    fun `a stale reference result is ignored`() {
        val obs = listOf(connectFailed("a"), connectFailed("b"))
        val stale = evidence(obs, validated = false, reference = true).copy(referenceProbeEpochMillis = 0L)
        assertEquals(RestrictionClass.POSSIBLE_FULL_SHUTDOWN, RestrictionClassifier.classify(stale, nowEpochMillis = RestrictionClassifier.DEFAULT_STALE_AFTER_MILLIS + 1))
    }
}
