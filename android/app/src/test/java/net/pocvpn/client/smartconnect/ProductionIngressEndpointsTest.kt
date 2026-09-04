package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.ingressKind
import net.pocvpn.client.reachability.PathCandidateBuilder
import net.pocvpn.client.reachability.ReachabilityEvidenceSummary
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B31 - proves the real production Stockholm-ingress-to-Germany-exit
 * topology [ProductionIngressEndpoints] describes is enough, on its own, for
 * the ALREADY-GENERIC [PathCandidateBuilder]/[AutoGatewaySelector] pipeline
 * to construct a real CHAIN_DIRECT candidate - the exact gap the physical
 * Oppo CPH2173 test (main @ fac18bb) found: the client dialed Stockholm's
 * ordinary EXIT (16.170.208.231:2083, selectedPath=DIRECT) because no
 * INGRESS-role descriptor for Stockholm existed anywhere the reachability
 * pipeline could see. Deliberately does not touch path SCORING - only
 * proves the candidate EXISTS, same as PathCandidateBuilderTest/
 * AutoGatewaySelectorTest's own already-generic relay tests.
 */
class ProductionIngressEndpointsTest {

    private val germanyExit = ProductionGatewayEndpoints.descriptorFor(
        ProductionGatewayCatalog.GERMANY, xrayAvailable = true, xrayTlsAvailable = false,
    )

    private fun reachable(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, 0, true, true, RestrictionClass.UNKNOWN, endpointSpecificReachableAgeMillis = 0),
    )

    /**
     * A never-dialed endpoint's OWN reachability - no endpoint-specific
     * evidence, UNKNOWN state - matching a genuine first-ever CHAIN_DIRECT
     * attempt at THIS isolated layer (unlike [reachable], which
     * unconditionally claims confirmed evidence). Proves
     * [AutoGatewaySelector.buildRelayedCandidates]'s own [PathScorer] rule 3
     * ("transport-wide UNREACHABLE, no hop confirmed reachable ->
     * ineligible") in isolation.
     *
     * This does NOT reproduce the full, real 2026-09 field-test bug on its
     * own - that requires [net.pocvpn.client.reachability.ReachabilityEngine.assess]'s
     * OWN fallback tier (which maps a poisoned shared TransportHealth
     * directly into ReachabilityState.UNREACHABLE, tripping PathScorer's
     * stronger, unconditional rule 2 instead) - a MainViewModel-level
     * concern this isolated function's callers supply as an opaque,
     * already-computed [EndpointReachability]. See
     * `MainViewModelIngressWiringTest`'s "the real production Stockholm
     * CHAIN_DIRECT candidate survives..." test for the full, real,
     * end-to-end reproduction and proof through the actual
     * `reachabilityFor`/`ReachabilityEngine.assess` pipeline.
     */
    private fun unconfirmed(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.UNKNOWN,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, RestrictionClass.UNKNOWN),
    )

    private fun healthyRegistry(kind: TransportKind): TransportRegistry = TransportRegistry.build(
        listOf(TransportDescriptor(kind = kind, status = TransportStatus.AVAILABLE, capabilities = TransportCapabilities.amneziaWg(), factory = { throw UnsupportedOperationException() })),
    )

    // --- 1/2: Stockholm's ingress is represented as INGRESS/DIRECT_IP, not an ordinary EXIT transport ---

    @Test
    fun `Stockholm ingress descriptor carries only the INGRESS role, never GATEWAY or EXIT`() {
        assertEquals(setOf(EndpointRole.INGRESS), ProductionIngressEndpoints.STOCKHOLM.roles)
    }

    @Test
    fun `Stockholm ingress kind is DIRECT_IP`() {
        val binding = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)
        assertNotNull(binding)
        assertEquals(IngressKind.DIRECT_IP, binding!!.ingressKind())
    }

    @Test
    fun `Stockholm ingress dials the real deployed port 2093, distinct from its own ordinary REALITY port 2053`() {
        val binding = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)!!
        assertEquals(2093, binding.port)
        assertEquals(ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost, binding.host)

        val ordinaryStockholm = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.STOCKHOLM, xrayAvailable = true, xrayTlsAvailable = false)
        assertNotEquals(binding.port, ordinaryStockholm.bindingFor(TransportKind.XRAY_REALITY)!!.port)
    }

    @Test
    fun `Stockholm ingress carries a DIFFERENT EndpointId from its own ordinary GATEWAY-EXIT descriptor`() {
        assertNotEquals(ProductionGatewayCatalog.STOCKHOLM.endpointId, ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID)
    }

    // --- 3: Germany remains the EXIT ---

    @Test
    fun `Stockholm ingress relays to Germany's real EXIT endpoint id`() {
        assertEquals(germanyExit.id, ProductionIngressEndpoints.STOCKHOLM.relayTo)
        assertTrue(EndpointRole.EXIT in germanyExit.roles)
    }

    // --- 4/5: the production data produces a real Relayed/CHAIN_DIRECT candidate over REALITY ---

    @Test
    fun `PathCandidateBuilder builds a real Relayed candidate for the production Stockholm-to-Germany topology`() {
        // XRAY_REALITY on both hops - the SAME transport the real deployed
        // relay-upstream actually dials Germany over (gateway/config/
        // ingress.env's own NOVA_INGRESS_UPSTREAM_TRANSPORT=reality).
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress = ProductionIngressEndpoints.STOCKHOLM,
            exit = germanyExit,
            ingressTransport = TransportKind.XRAY_REALITY,
            exitTransport = TransportKind.XRAY_REALITY,
            ingressReachability = reachable(ProductionIngressEndpoints.STOCKHOLM.id, TransportKind.XRAY_REALITY),
            exitReachability = reachable(germanyExit.id, TransportKind.XRAY_REALITY),
        )
        assertNotNull(candidate)
        assertEquals(TransportKind.XRAY_REALITY, candidate!!.transport)
        assertEquals(IngressKind.DIRECT_IP, candidate.ingressKind)
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, candidate.ingress.endpoint.id)
        assertEquals(germanyExit.id, candidate.exit.endpoint.id)
    }

    @Test
    fun `AutoGatewaySelector buildRelayedCandidates produces a CHAIN_DIRECT-shaped candidate for the real production topology`() {
        // germanyExit declares both AMNEZIA_WG (always present) and
        // XRAY_REALITY (xrayAvailable=true) - buildRelayedCandidates
        // correctly scores every (ingress, exit) transport pair
        // independently, so BOTH a REALITY->AMNEZIA_WG and a
        // REALITY->XRAY_REALITY relayed candidate are legitimately
        // produced. The real deployed relay-upstream (gateway/config/
        // ingress.env's own NOVA_INGRESS_UPSTREAM_TRANSPORT) dials Germany
        // over XRAY_REALITY specifically - assert that exact pairing exists
        // rather than over-constraining the total candidate count.
        val candidates = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ProductionIngressEndpoints.STOCKHOLM, germanyExit),
            registryFor = { healthyRegistry(TransportKind.XRAY_REALITY) },
            reachabilityFor = { id, kind -> reachable(id, kind) },
            transportHealthFor = { TransportHealth(state = TransportHealthState.HEALTHY) },
            historyFor = { _, _ -> null },
        )
        assertTrue(candidates.isNotEmpty())
        val viaRealityUpstream = candidates.single { it.exitTransport == TransportKind.XRAY_REALITY }
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, viaRealityUpstream.ingressEndpointId)
        assertEquals(germanyExit.id, viaRealityUpstream.exitEndpointId)
        assertEquals(TransportKind.XRAY_REALITY, viaRealityUpstream.ingressTransport)
        assertEquals(IngressKind.DIRECT_IP, viaRealityUpstream.ingressKind)
    }

    // --- PR #58 field-test fix: a DIFFERENT endpoint's Direct XRAY_REALITY
    // failures must never poison the relay's own eligibility ---

    @Test
    fun `a shared kind-wide UNREACHABLE health (Germany's own blocked Direct REALITY port) does not exclude a never-yet-dialed Stockholm-ingress relay candidate when scoped health is healthy`() {
        // Reproduces the exact 2026-09 Russia field-test bug: Germany's own
        // Direct XRAY_REALITY dial (a different endpoint, a different port,
        // 2053) correctly failed twice, flipping the SHARED
        // transportHealthFor(XRAY_REALITY) to UNREACHABLE. The ingress hop
        // uses `unconfirmed` (UNKNOWN reachability, no endpoint-specific
        // evidence) - exactly what a genuine first-ever attempt at
        // stockholm-ingress-1 looks like, never `reachable`'s unconditional
        // confirmed-REACHABLE stub, which would never exercise PathScorer's
        // "UNREACHABLE transport health, no hop confirmed reachable"
        // exclusion rule at all. Before this fix, buildRelayedCandidates
        // read the SAME shared bucket for the Stockholm-ingress candidate
        // too and silently dropped it from ranking - CHAIN_DIRECT was never
        // attempted, matching the observed zero requests at the Stockholm
        // ingress control plane.
        val sharedUnreachableHealth = TransportHealth(state = TransportHealthState.UNREACHABLE, consecutiveFailures = 2)
        val scopedUnknownHealth = TransportHealth(state = TransportHealthState.UNKNOWN)

        val candidates = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ProductionIngressEndpoints.STOCKHOLM, germanyExit),
            registryFor = { healthyRegistry(TransportKind.XRAY_REALITY) },
            // Neither hop confirmed reachable - otherwise rule 3's own "...
            // UNLESS some hop is confirmed REACHABLE" escape would trigger
            // regardless of transport health, and this test would prove
            // nothing about ingressTransportHealthFor at all.
            reachabilityFor = { id, kind -> unconfirmed(id, kind) },
            transportHealthFor = { sharedUnreachableHealth },
            historyFor = { _, _ -> null },
            // ingressTransportHealthFor scoped to the ingress endpoint's own
            // (never-yet-dialed) evidence - UNKNOWN, not poisoned by
            // Germany's unrelated Direct failures.
            ingressTransportHealthFor = { _, _ -> scopedUnknownHealth },
        )

        val viaRealityUpstream = candidates.singleOrNull { it.exitTransport == TransportKind.XRAY_REALITY }
        assertNotNull(
            "the Stockholm-ingress CHAIN_DIRECT candidate must remain eligible when its OWN scoped health is fine, even though the shared kind-wide bucket is UNREACHABLE",
            viaRealityUpstream,
        )
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, viaRealityUpstream!!.ingressEndpointId)
    }

    @Test
    fun `omitting ingressTransportHealthFor falls back to the shared transportHealthFor byte-for-byte - the pre-fix rule-3 exclusion is reproducible without the new parameter`() {
        // Proves the default value truly preserves old behavior (every
        // pre-existing caller/test is unaffected unless it opts in) AND
        // documents PathScorer's rule-3 exclusion shape in isolation: with
        // no scoping supplied at all, a shared UNREACHABLE bucket DOES drop
        // a candidate whose own reachability carries no confirmed evidence.
        val candidates = AutoGatewaySelector.buildRelayedCandidates(
            manifestEndpoints = listOf(ProductionIngressEndpoints.STOCKHOLM, germanyExit),
            registryFor = { healthyRegistry(TransportKind.XRAY_REALITY) },
            reachabilityFor = { id, kind -> if (id == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID) unconfirmed(id, kind) else unconfirmed(id, kind) },
            transportHealthFor = { TransportHealth(state = TransportHealthState.UNREACHABLE, consecutiveFailures = 2) },
            historyFor = { _, _ -> null },
        )

        assertTrue(
            "without endpoint-scoped health, and with no hop confirmed reachable, the shared UNREACHABLE bucket must still (pre-fix behavior) exclude the relay candidate",
            candidates.none { it.exitTransport == TransportKind.XRAY_REALITY },
        )
    }

    // --- 6/7: existing standalone DIRECT candidates for both gateways remain unaffected ---

    @Test
    fun `Stockholm's existing standalone DIRECT EXIT descriptor is untouched by the new ingress object`() {
        val ordinaryStockholm = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.STOCKHOLM, xrayAvailable = true, xrayTlsAvailable = true)
        assertEquals(setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), ordinaryStockholm.roles)
        assertEquals(ProductionGatewayCatalog.STOCKHOLM.endpointId, ordinaryStockholm.id)
        assertTrue(ordinaryStockholm.supports(TransportKind.AMNEZIA_WG))
        val directCandidate = PathCandidateBuilder.buildDirect(
            ordinaryStockholm, TransportKind.AMNEZIA_WG, reachable(ordinaryStockholm.id, TransportKind.AMNEZIA_WG),
        )
        assertNotNull(directCandidate)
    }

    @Test
    fun `Germany's ordinary DIRECT candidate still exists alongside its new EXIT role in a relay`() {
        val directCandidate = PathCandidateBuilder.buildDirect(
            germanyExit, TransportKind.AMNEZIA_WG, reachable(germanyExit.id, TransportKind.AMNEZIA_WG),
        )
        assertNotNull(directCandidate)
        assertEquals(germanyExit.id, directCandidate!!.gateway.endpoint.id)
    }

    // --- 8: no per-device identity/secret appears in this data ---

    @Test
    fun `Stockholm ingress binding metadata carries only the ingressKind key - no identity or secret material`() {
        val binding = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)!!
        assertEquals(setOf("ingressKind"), binding.metadata.keys)
    }

    // --- 11: pinning - the candidate's exit hop stays pinned to what it was actually built from ---

    @Test
    fun `a built candidate keeps its own pinned Germany snapshot even if a caller later resolves a different exit descriptor for the same id`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress = ProductionIngressEndpoints.STOCKHOLM,
            exit = germanyExit,
            ingressTransport = TransportKind.XRAY_REALITY,
            exitTransport = TransportKind.AMNEZIA_WG,
            ingressReachability = reachable(ProductionIngressEndpoints.STOCKHOLM.id, TransportKind.XRAY_REALITY),
            exitReachability = reachable(germanyExit.id, TransportKind.AMNEZIA_WG),
        )!!
        val rotatedGermany = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.GERMANY, xrayAvailable = false, xrayTlsAvailable = false)
        // The rotated resolve no longer supports XRAY_REALITY/etc as configured here -
        // the ALREADY-BUILT candidate must not reflect that; it keeps its own pin.
        assertEquals("152.70.43.1", candidate.exit.binding.host)
        assertFalse(rotatedGermany.id != germanyExit.id)
        assertEquals(51820, candidate.exit.binding.port)
    }
}
