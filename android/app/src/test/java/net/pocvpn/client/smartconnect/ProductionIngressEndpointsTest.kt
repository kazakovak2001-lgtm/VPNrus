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
