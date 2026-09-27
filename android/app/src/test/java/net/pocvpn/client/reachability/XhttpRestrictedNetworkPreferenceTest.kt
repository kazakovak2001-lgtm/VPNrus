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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL2 - proves, at the RANKING level (PathScorer.rank over every direct
 * transport the client can dial), the acceptance criteria docs/ROADMAP.md's
 * B-WL2 row sets for XHTTP as the preferred path on restricted networks. The
 * mechanism itself is B-WL5's `PathScorer.restrictionPreference` (no new
 * production code): these tests pin the behaviour the ROADMAP promises.
 *
 * Every candidate is scored with the SAME TransportCapabilities profile its
 * production VpnTransport declares (VlessXhttpTransport ->
 * xrayXhttpAdapterShell, etc.), because that is what MainViewModel and
 * AutoGatewaySelector pass: `registry.descriptorFor(kind).capabilities`.
 */
class XhttpRestrictedNetworkPreferenceTest {

    private val productionCapabilities = mapOf(
        TransportKind.AMNEZIA_WG to TransportCapabilities.amneziaWg(),
        TransportKind.XRAY_REALITY to TransportCapabilities.xrayRealityAdapterShell(),
        TransportKind.TLS_TCP to TransportCapabilities.xrayTlsAdapterShell(),
        TransportKind.XRAY_XHTTP to TransportCapabilities.xrayXhttpAdapterShell(),
    )

    private val registry: TransportRegistry = TransportRegistry.build(
        productionCapabilities.map { (kind, caps) ->
            TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = caps, factory = { FakeVpnTransport() })
        },
    )

    private val healthy = TransportHealth(state = TransportHealthState.HEALTHY)

    private fun direct(
        kind: TransportKind,
        restrictionClass: RestrictionClass,
        state: ReachabilityState = ReachabilityState.REACHABLE,
        endpointSpecificReachable: Boolean? = null,
    ): PathCandidate.Direct {
        val endpoint = EndpointDescriptor(
            EndpointId("gw-${kind.name.lowercase()}"), setOf(EndpointRole.GATEWAY), "eu", "acme",
            transports = listOf(EndpointTransportBinding(kind, "203.0.113.1", 443)),
        )
        val reachability = EndpointReachability(
            endpoint.id, kind, state,
            evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, endpointSpecificReachable, true, restrictionClass),
        )
        return PathCandidateBuilder.buildDirect(endpoint, kind, reachability)!!
    }

    private fun score(
        candidate: PathCandidate,
        health: TransportHealth = healthy,
        history: PathHistoryEntry? = null,
    ): PathScorer.PathScoreResult =
        PathScorer.score(candidate, registry, productionCapabilities.getValue(candidate.transport), health, history, false)

    private fun rankedKinds(restrictionClass: RestrictionClass): List<PathScorer.PathScoreResult> =
        PathScorer.rank(productionCapabilities.keys.map { score(direct(it, restrictionClass)) })

    @Test
    fun `XRAY_XHTTP is the only production transport profile declared suitable for restrictive networks`() {
        assertEquals(
            listOf(TransportKind.XRAY_XHTTP),
            productionCapabilities.filterValues { it.suitableForRestrictiveNetworks }.keys.toList(),
        )
        val xhttp = TransportCapabilities.xrayXhttpAdapterShell()
        assertTrue(xhttp.usesTcp)
        assertFalse(xhttp.usesUdp)
    }

    @Test
    fun `under POSSIBLE_UDP_FILTERING XHTTP ranks first and the UDP-only AWG ranks last`() {
        val ranked = rankedKinds(RestrictionClass.POSSIBLE_UDP_FILTERING)
        assertEquals(TransportKind.XRAY_XHTTP, ranked.first().candidate.transport)
        assertEquals(TransportKind.AMNEZIA_WG, ranked.last().candidate.transport)
        assertTrue(PathScorer.Reason.RESTRICTION_FAVORS_TCP_TRANSPORT.name in ranked.first().reasons)
        assertTrue(PathScorer.Reason.RESTRICTION_PENALIZES_UDP_TRANSPORT.name in ranked.last().reasons)
    }

    @Test
    fun `XHTTP is never the sole candidate - every eligible transport stays in the ranking`() {
        val ranked = rankedKinds(RestrictionClass.POSSIBLE_UDP_FILTERING)
        assertEquals(productionCapabilities.keys, ranked.map { it.candidate.transport }.toSet())
        assertTrue(ranked.all { it.eligible })
    }

    @Test
    fun `without restriction evidence no transport receives a restriction preference`() {
        for (restrictionClass in listOf(RestrictionClass.UNKNOWN, RestrictionClass.NO_RESTRICTION_OBSERVED)) {
            val ranked = rankedKinds(restrictionClass)
            assertTrue(
                "no restriction reason expected under $restrictionClass",
                ranked.all { result -> result.reasons.none { it.startsWith("restriction=") } },
            )
        }
    }

    @Test
    fun `the XHTTP preference never beats worse transport health`() {
        val xhttpDegraded = score(direct(TransportKind.XRAY_XHTTP, RestrictionClass.POSSIBLE_UDP_FILTERING), TransportHealth(state = TransportHealthState.DEGRADED))
        val realityHealthy = score(direct(TransportKind.XRAY_REALITY, RestrictionClass.POSSIBLE_UDP_FILTERING))
        assertTrue(realityHealthy.score > xhttpDegraded.score)
    }

    @Test
    fun `the XHTTP preference never beats worse reachability`() {
        val xhttpDegraded = score(direct(TransportKind.XRAY_XHTTP, RestrictionClass.POSSIBLE_UDP_FILTERING, state = ReachabilityState.DEGRADED))
        val realityReachable = score(direct(TransportKind.XRAY_REALITY, RestrictionClass.POSSIBLE_UDP_FILTERING))
        assertTrue(realityReachable.score > xhttpDegraded.score)
    }

    @Test
    fun `restriction evidence never makes a freshly-unreachable XHTTP endpoint eligible`() {
        val result = score(
            direct(TransportKind.XRAY_XHTTP, RestrictionClass.POSSIBLE_UDP_FILTERING, state = ReachabilityState.UNREACHABLE, endpointSpecificReachable = false),
        )
        assertFalse(result.eligible)
        assertEquals(Long.MIN_VALUE, result.score)
    }

    @Test
    fun `a real local success history on this network outranks the XHTTP preference`() {
        val history = PathHistoryEntry(successCount = 5, failureCount = 0, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = true)
        val realityWithHistory = score(direct(TransportKind.XRAY_REALITY, RestrictionClass.POSSIBLE_UDP_FILTERING), history = history)
        val xhttpNoHistory = score(direct(TransportKind.XRAY_XHTTP, RestrictionClass.POSSIBLE_UDP_FILTERING))
        assertTrue(realityWithHistory.score > xhttpNoHistory.score)
    }

    @Test
    fun `under POSSIBLE_EARLY_DROP XHTTP is not penalized while plain direct REALITY and TLS are`() {
        val ranked = rankedKinds(RestrictionClass.POSSIBLE_EARLY_DROP)
        val byKind = ranked.associateBy { it.candidate.transport }
        assertTrue(byKind.getValue(TransportKind.XRAY_XHTTP).reasons.none { it.startsWith("restriction=") })
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP)) {
            assertTrue(PathScorer.Reason.RESTRICTION_PENALIZES_EARLY_DROP_PRONE.name in byKind.getValue(kind).reasons)
            assertTrue(byKind.getValue(TransportKind.XRAY_XHTTP).score > byKind.getValue(kind).score)
        }
    }

    @Test
    fun `under POSSIBLE_HARD_WHITELIST direct candidates are treated alike regardless of transport (B28 relay-vs-direct rule unchanged)`() {
        val ranked = rankedKinds(RestrictionClass.POSSIBLE_HARD_WHITELIST)
        assertTrue(ranked.all { PathScorer.Reason.RESTRICTION_PENALIZES_DIRECT.name in it.reasons })
        assertTrue(ranked.none { PathScorer.Reason.RESTRICTION_FAVORS_TCP_TRANSPORT.name in it.reasons })
    }
}
