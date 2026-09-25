package net.pocvpn.client.reachability

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL5 - network-aware candidate ordering through the ONE existing ranking
 * authority (PathScorer.score/rank), using each transport's REAL capability
 * profile from TransportCapabilities - proving the candidate ORDER (not just
 * the classification enum) changes with the network classification, and
 * that the existing PathHistoryStore failure memory keeps a failed candidate
 * from being retried first.
 */
class AdaptiveTransportSelectionTest {

    private val capabilities = mapOf(
        TransportKind.AMNEZIA_WG to TransportCapabilities.amneziaWg(),
        TransportKind.XRAY_REALITY to TransportCapabilities.xrayRealityAdapterShell(),
        TransportKind.XRAY_XHTTP to TransportCapabilities.xrayXhttpAdapterShell(),
        TransportKind.TLS_TCP to TransportCapabilities.xrayTlsAdapterShell(),
    )

    private val registry = TransportRegistry.build(
        capabilities.map { (kind, caps) -> TransportDescriptor(kind, TransportStatus.AVAILABLE, caps, factory = { FakeVpnTransport(kind = kind) }) },
    )

    private val health = TransportHealth(state = TransportHealthState.UNKNOWN)

    private fun reach(id: EndpointId, kind: TransportKind, restriction: RestrictionClass) = EndpointReachability(
        id, kind, ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, restriction),
    )

    private val gateway = EndpointDescriptor(
        EndpointId("gw1"), setOf(EndpointRole.GATEWAY), "eu", "provider-a",
        transports = listOf(
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820),
            EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.1", 443),
            EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.1", 8443),
        ),
    )
    private val ingress = EndpointDescriptor(
        EndpointId("in1"), setOf(EndpointRole.INGRESS), "ru", "provider-b",
        transports = listOf(EndpointTransportBinding(TransportKind.XRAY_XHTTP, "198.51.100.7", 443).withIngressKind(IngressKind.CDN_FRONTED)),
        relayTo = EndpointId("gw1"),
    )
    private val exit = EndpointDescriptor(
        EndpointId("gw1"), setOf(EndpointRole.EXIT), "eu", "provider-a",
        transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.1", 443)),
    )

    private fun candidates(restriction: RestrictionClass): List<PathCandidate> = listOf(
        PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG, restriction))!!,
        PathCandidateBuilder.buildDirect(gateway, TransportKind.XRAY_REALITY, reach(gateway.id, TransportKind.XRAY_REALITY, restriction))!!,
        PathCandidateBuilder.buildDirect(gateway, TransportKind.TLS_TCP, reach(gateway.id, TransportKind.TLS_TCP, restriction))!!,
        PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.XRAY_XHTTP, TransportKind.XRAY_REALITY,
            reach(ingress.id, TransportKind.XRAY_XHTTP, restriction), reach(exit.id, TransportKind.XRAY_REALITY, restriction),
        )!!,
    )

    private fun label(c: PathCandidate) = when (c) {
        is PathCandidate.Direct -> c.transport.name
        is PathCandidate.Relayed -> "RELAY_${c.transport.name}"
    }

    private fun ranked(restriction: RestrictionClass, history: Map<String, PathHistoryEntry> = emptyMap(), now: Long = Long.MAX_VALUE): List<String> =
        PathScorer.rank(
            candidates(restriction).map { c ->
                PathScorer.score(c, registry, capabilities.getValue(c.transport), health, history[c.id], false, now)
            },
        ).map { label(it.candidate) }

    @Test
    fun `NORMAL network keeps the existing preferred order - AWG first`() {
        val normal = listOf("AMNEZIA_WG", "XRAY_REALITY", "RELAY_XRAY_XHTTP", "TLS_TCP")
        assertEquals(normal, ranked(RestrictionClass.UNKNOWN))
        assertEquals(normal, ranked(RestrictionClass.NO_RESTRICTION_OBSERVED))
    }

    @Test
    fun `UDP-limited network moves the XHTTP TCP path first and AWG last`() {
        assertEquals(listOf("RELAY_XRAY_XHTTP", "XRAY_REALITY", "TLS_TCP", "AMNEZIA_WG"), ranked(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING))
    }

    @Test
    fun `possible whitelist prefers the allowed-ingress relay over every direct path`() {
        assertEquals(listOf("RELAY_XRAY_XHTTP", "AMNEZIA_WG", "XRAY_REALITY", "TLS_TCP"), ranked(RestrictionClass.POSSIBLE_HARD_WHITELIST))
    }

    @Test
    fun `early drop prefers the relay, keeps UDP neutral and demotes long-lived direct TCP streams`() {
        assertEquals(listOf("RELAY_XRAY_XHTTP", "AMNEZIA_WG", "XRAY_REALITY", "TLS_TCP"), ranked(RestrictionClass.POSSIBLE_EARLY_DROP))
    }

    @Test
    fun `full shutdown changes nothing - no transport choice helps, the bounded attempt budget applies`() {
        assertEquals(ranked(RestrictionClass.UNKNOWN), ranked(RestrictionClass.POSSIBLE_FULL_SHUTDOWN))
    }

    @Test
    fun `candidate order really differs between classifications, not just the enum`() {
        val orders = listOf(
            RestrictionClass.UNKNOWN, RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING,
            RestrictionClass.POSSIBLE_HARD_WHITELIST, RestrictionClass.POSSIBLE_EARLY_DROP,
        ).map { ranked(it) }
        assertNotEquals(orders[0], orders[1])
        assertNotEquals(orders[0], orders[2])
        assertNotEquals(orders[1], orders[2])
        assertNotEquals(orders[0], orders[3])
    }

    @Test
    fun `failover A fails, B fails, C succeeds - and failure memory keeps A and B from being retried first`() {
        val now = 1_000_000L
        val restriction = RestrictionClass.POSSIBLE_HARD_WHITELIST
        val store = mutableMapOf<String, PathHistoryEntry>()
        fun record(label: String, success: Boolean) {
            val c = candidates(restriction).first { label(it) == label }
            val prev = store[c.id]
            store[c.id] = PathHistoryEntry(
                successCount = (prev?.successCount ?: 0) + if (success) 1 else 0,
                failureCount = (prev?.failureCount ?: 0) + if (success) 0 else 1,
                lastOutcomeEpochMillis = now,
                lastOutcomeSuccess = success,
                consecutiveFailures = if (success) 0 else (prev?.consecutiveFailures ?: 0) + 1,
            )
        }

        // One bounded session walks the ranked list; every terminal handshake
        // failure is eligible for the next candidate (the existing policy).
        val sessionOrder = ranked(restriction, store, now)
        val outcomes = mapOf("RELAY_XRAY_XHTTP" to false, "AMNEZIA_WG" to false, "XRAY_REALITY" to true)
        val attempted = mutableListOf<String>()
        for (label in sessionOrder) {
            attempted += label
            val ok = outcomes.getValue(label)
            record(label, ok)
            if (ok) break
            assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(TransportState.HandshakeFailed, VpnError.HandshakeTimeout))
        }
        assertEquals(listOf("RELAY_XRAY_XHTTP", "AMNEZIA_WG", "XRAY_REALITY"), attempted)

        // Next session on the same network: the candidate that actually worked
        // leads, and the UDP transport that failed under whitelist evidence is
        // not retried ahead of it.
        val next = ranked(restriction, store, now + 1)
        assertEquals("XRAY_REALITY", next.first())
        assertTrue(next.indexOf("AMNEZIA_WG") > next.indexOf("XRAY_REALITY"))
    }

    @Test
    fun `failure-memory cooldown is bounded - it expires instead of blacklisting forever`() {
        val now = 1_000_000L
        val awg = candidates(RestrictionClass.UNKNOWN).first { label(it) == "AMNEZIA_WG" }
        val failedOnce = mapOf(awg.id to PathHistoryEntry(1, 1, now, lastOutcomeSuccess = false, consecutiveFailures = 1))
        val withinWindow = PathScorer.score(awg, registry, TransportCapabilities.amneziaWg(), health, failedOnce[awg.id], false, now + 1)
        val afterWindow = PathScorer.score(awg, registry, TransportCapabilities.amneziaWg(), health, failedOnce[awg.id], false, now + PathScorer.FAILURE_COOLDOWN_WINDOW_MILLIS + 1)
        assertTrue(PathScorer.Reason.FAILURE_COOLDOWN.name in withinWindow.reasons)
        assertTrue(afterWindow.score > withinWindow.score)
    }
}
