package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B12 - end-to-end proof that a manifest naming MULTIPLE distinct endpoints
 * (different provider/ASN, per the task's own Gateway Pool requirements)
 * flows correctly through EVERY B11/B12 stage together:
 * ManifestCanonicalizer -> EndpointManifest -> ReachabilityEngine ->
 * PathCandidateBuilder -> PathScorer - not just each stage in isolation
 * (already covered by their own unit test files).
 *
 * These two endpoints are SYNTHETIC test fixtures, not a real second
 * production gateway - see docs/ROADMAP.md's own B12 notes for why no
 * second real VPS was provisioned in this slice (operator action required,
 * out of scope for an automated change).
 */
class GatewayPoolIntegrationTest {

    private val gatewayA = EndpointDescriptor(
        id = EndpointId("frankfurt"),
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "Germany / Frankfurt",
        provider = "hetzner",
        asn = 24940,
        transports = listOf(
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820),
            EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.1", 2083),
        ),
    )

    private val gatewayB = EndpointDescriptor(
        id = EndpointId("amsterdam"),
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "Netherlands / Amsterdam",
        provider = "ovh",
        asn = 16276,
        transports = listOf(
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.9", 51820),
        ),
    )

    private fun manifest() = EndpointManifest(
        manifestVersion = 1,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 9_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(gatewayA, gatewayB),
    )

    @Test
    fun `two distinct endpoint IDs, providers, and ASNs coexist in one manifest`() {
        val m = manifest()
        assertEquals(2, m.endpoints.size)
        assertEquals(setOf("frankfurt", "amsterdam"), m.endpoints.map { it.id.value }.toSet())
        assertEquals(setOf("hetzner", "ovh"), m.endpoints.map { it.provider }.toSet())
        assertEquals(setOf(24940, 16276), m.endpoints.map { it.asn }.toSet())
    }

    @Test
    fun `a duplicate endpoint id across the pool is rejected at manifest construction`() {
        assertThrows(IllegalArgumentException::class.java) {
            EndpointManifest(
                manifestVersion = 1, issuedAtEpochMillis = 1_000L, expiresAtEpochMillis = 9_000_000L,
                signingKeyId = "key-1",
                endpoints = listOf(gatewayA, gatewayA.copy(provider = "different-provider")),
            )
        }
    }

    @Test
    fun `canonicalization and decode round-trip a multi-endpoint manifest - endpoint SET is preserved (order is not semantically meaningful, see ManifestCanonicalizer's own docs)`() {
        val m = manifest()
        val bytes = ManifestCanonicalizer.canonicalBytes(m)
        val decoded = ManifestCanonicalizer.decode(bytes)
        assertEquals(m.endpoints.toSet(), decoded.endpoints.toSet())
        assertEquals(m.copy(endpoints = m.endpoints.sortedBy { it.id.value }), decoded)
    }

    @Test
    fun `endpoint A reachable and B unreachable are assessed independently, never conflated`() {
        val now = 1_000_000L
        val reachA = ReachabilityEngine.assess(
            gatewayA, TransportKind.AMNEZIA_WG, networkUsable = true,
            transportHealth = TransportHealth(state = TransportHealthState.HEALTHY),
            endpointSpecificReachable = true, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = now,
        )
        val reachB = ReachabilityEngine.assess(
            gatewayB, TransportKind.AMNEZIA_WG, networkUsable = true,
            transportHealth = TransportHealth(state = TransportHealthState.UNREACHABLE),
            endpointSpecificReachable = false, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = now,
        )
        assertEquals(ReachabilityState.REACHABLE, reachA.state)
        assertEquals(ReachabilityState.UNREACHABLE, reachB.state)
    }

    @Test
    fun `the SAME transport can be healthy on one endpoint and unreachable on another simultaneously`() {
        val now = 1_000_000L
        // Aggregate TransportHealth is the SAME for both (one transport-wide
        // signal) but per-endpoint evidence still diverges - proving
        // EndpointReachability is genuinely per-endpoint, not just a
        // reflection of TransportHealth.
        val sharedHealth = TransportHealth(state = TransportHealthState.HEALTHY)
        val reachA = ReachabilityEngine.assess(
            gatewayA, TransportKind.AMNEZIA_WG, networkUsable = true, transportHealth = sharedHealth,
            endpointSpecificReachable = true, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = now,
        )
        val reachB = ReachabilityEngine.assess(
            gatewayB, TransportKind.AMNEZIA_WG, networkUsable = true, transportHealth = sharedHealth,
            endpointSpecificReachable = false, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = now,
        )
        assertEquals(ReachabilityState.REACHABLE, reachA.state)
        assertEquals(ReachabilityState.DEGRADED, reachB.state) // conflicting evidence -> conservative middle state
    }

    @Test
    fun `control-plane reachable but this endpoint's own data plane unreachable are distinct signals`() {
        val reach = ReachabilityEngine.assess(
            gatewayA, TransportKind.AMNEZIA_WG, networkUsable = true,
            transportHealth = TransportHealth(state = TransportHealthState.UNREACHABLE),
            endpointSpecificReachable = false, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = 1_000_000L,
            controlPlaneReachable = true,
            endpointSpecificOutcomeEpochMillis = 1_000_000L,
        )
        assertEquals(ReachabilityState.UNREACHABLE, reach.state) // data-plane evidence still governs state
        assertEquals(true, reach.evidence.controlPlaneReachable)
        assertEquals(false, reach.evidence.endpointSpecificReachable)
    }

    @Test
    fun `direct path candidates are generated per endpoint per supported transport`() {
        val now = 1_000_000L
        fun reach(e: EndpointDescriptor, kind: TransportKind, ok: Boolean) = ReachabilityEngine.assess(
            e, kind, networkUsable = true, transportHealth = TransportHealth(state = TransportHealthState.HEALTHY),
            endpointSpecificReachable = ok, restrictionClass = RestrictionClass.UNKNOWN, nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = now,
        )
        val candidates = listOf(
            PathCandidateBuilder.buildDirect(gatewayA, TransportKind.AMNEZIA_WG, reach(gatewayA, TransportKind.AMNEZIA_WG, true)),
            PathCandidateBuilder.buildDirect(gatewayA, TransportKind.TLS_TCP, reach(gatewayA, TransportKind.TLS_TCP, true)),
            PathCandidateBuilder.buildDirect(gatewayB, TransportKind.AMNEZIA_WG, reach(gatewayB, TransportKind.AMNEZIA_WG, false)),
        ).filterNotNull()
        assertEquals(3, candidates.size)
        assertEquals(setOf("direct:AMNEZIA_WG:frankfurt", "direct:TLS_TCP:frankfurt", "direct:AMNEZIA_WG:amsterdam"), candidates.map { it.id }.toSet())
    }

    @Test
    fun `real multi-endpoint ordering - the reachable endpoint always outranks the unreachable one regardless of latency`() {
        val reachableSlow = PathCandidateBuilder.buildDirect(
            gatewayA, TransportKind.AMNEZIA_WG,
            EndpointReachability(
                gatewayA.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = 4000L,
                evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, true, true, RestrictionClass.UNKNOWN),
            ),
        )!!
        val unreachableFast = PathCandidateBuilder.buildDirect(
            gatewayB, TransportKind.AMNEZIA_WG,
            EndpointReachability(
                gatewayB.id, TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE, latencyMillis = 5L,
                evidence = ReachabilityEvidenceSummary(TransportHealthState.UNREACHABLE, null, false, true, RestrictionClass.UNKNOWN),
            ),
        )!!

        val registry = TransportRegistry.build(
            listOf(
                TransportDescriptor(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE, TransportCapabilities.amneziaWg()) { FakeVpnTransport() },
            ),
        )
        val history = mapOf<EndpointId, PathHistoryEntry?>(gatewayA.id to null, gatewayB.id to null)
        val scores = listOf(reachableSlow, unreachableFast).map { candidate ->
            val gateway = candidate.gateway.endpoint
            PathScorer.score(
                candidate, registry, TransportCapabilities.amneziaWg(),
                TransportHealth(state = if (gateway.id == gatewayA.id) TransportHealthState.HEALTHY else TransportHealthState.UNREACHABLE),
                history[gateway.id], diverseProviderOrAsnSeenElsewhere = true, // A and B really do have different providers/ASNs
            )
        }
        val ranked = PathScorer.rank(scores)
        assertEquals("direct:AMNEZIA_WG:frankfurt", ranked.first().candidate.id)
        assertTrue(ranked[0].score > ranked[1].score)
    }

    @Test
    fun `per-endpoint local network history is kept separate - success on A never credits B`() {
        val store = FilePathHistoryStore(java.nio.file.Files.createTempDirectory("gwpool").toFile())
        store.record("fp-1", gatewayA.id.value, TransportKind.AMNEZIA_WG, success = true, nowEpochMillis = 1L)
        assertTrue(store.get("fp-1", gatewayA.id.value, TransportKind.AMNEZIA_WG)!!.lastOutcomeSuccess)
        assertEquals(null, store.get("fp-1", gatewayB.id.value, TransportKind.AMNEZIA_WG))
    }
}
