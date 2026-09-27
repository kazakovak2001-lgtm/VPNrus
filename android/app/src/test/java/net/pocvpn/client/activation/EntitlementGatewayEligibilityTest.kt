package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B67.6 - pure decision-logic coverage for the entitlement -> eligible-
 * gateway mapping. No manifest/network/Android dependency - every input is
 * passed in directly, including the [EndpointId] -> [ProductionGatewayId]
 * lookup (a fake here, [net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byEndpointId]
 * in production - see `ProductionGatewayCatalogTest` for that real wiring's
 * own coverage).
 */
class EntitlementGatewayEligibilityTest {
    private val frankfurt = EndpointId("frankfurt")
    private val stockholm = EndpointId("stockholm")
    private val unknown = EndpointId("some-future-ingress")

    private val catalogLookup: (EndpointId) -> ProductionGatewayId? = {
        when (it) {
            frankfurt -> ProductionGatewayId.GERMANY
            stockholm -> ProductionGatewayId.STOCKHOLM
            else -> null
        }
    }

    @Test fun `Unscoped is always eligible for exactly the explicit requested gateway, regardless of manifest state`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Unscoped,
            trustedManifestEndpointIds = emptySet(),
            explicitRequestedGatewayId = ProductionGatewayId.STOCKHOLM,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.STOCKHOLM)), result)
    }

    @Test fun `Hinted with no trusted manifest at all is denied, never falls back to the explicit target`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(frankfurt)),
            trustedManifestEndpointIds = emptySet(),
            explicitRequestedGatewayId = ProductionGatewayId.GERMANY,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_TRUSTED_MANIFEST), result)
    }

    @Test fun `Hinted endpoint absent from the trusted manifest is denied`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(frankfurt)),
            trustedManifestEndpointIds = setOf(stockholm), // manifest trusts a DIFFERENT endpoint
            explicitRequestedGatewayId = ProductionGatewayId.GERMANY,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_HINTED_ENDPOINT_TRUSTED), result)
    }

    @Test fun `Hinted endpoint trusted but unknown to the product gateway catalog is denied`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(unknown)),
            trustedManifestEndpointIds = setOf(unknown), // manifest itself trusts it (e.g. an ingress-only entry)
            explicitRequestedGatewayId = ProductionGatewayId.GERMANY,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_HINTED_ENDPOINT_SUPPORTED), result)
    }

    @Test fun `Hinted endpoint both trusted and catalog-known is eligible`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(stockholm)),
            trustedManifestEndpointIds = setOf(frankfurt, stockholm),
            explicitRequestedGatewayId = ProductionGatewayId.GERMANY, // deliberately NOT the hinted gateway
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.STOCKHOLM)), result)
    }

    @Test fun `multiple trusted, catalog-known hints all become eligible, order preserved, deduplicated`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(stockholm, frankfurt, stockholm)),
            trustedManifestEndpointIds = setOf(frankfurt, stockholm),
            explicitRequestedGatewayId = ProductionGatewayId.GERMANY,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.STOCKHOLM, ProductionGatewayId.GERMANY)), result)
    }

    @Test fun `a mix of trusted-known and untrusted-unknown hints eligible-filters down to only the good ones`() {
        val result = EntitlementGatewayEligibility.resolve(
            scope = EntitlementScope.Hinted(listOf(unknown, frankfurt)),
            trustedManifestEndpointIds = setOf(frankfurt), // unknown is not even trusted here
            explicitRequestedGatewayId = ProductionGatewayId.STOCKHOLM,
            gatewayIdForEndpointId = catalogLookup,
        )
        assertEquals(GatewayEligibilityResult.Eligible(listOf(ProductionGatewayId.GERMANY)), result)
    }

    @Test fun `fromEnvelopeHints treats an empty hint list as Unscoped, never as an empty Hinted scope`() {
        assertEquals(EntitlementScope.Unscoped, EntitlementScope.fromEnvelopeHints(emptyList()))
        assertEquals(EntitlementScope.Hinted(listOf(frankfurt)), EntitlementScope.fromEnvelopeHints(listOf(frankfurt)))
    }

    // --- B67.7: filterEligibleEndpoints (the trusted-candidates + eligibility -> eligible-candidates step) ---

    private fun endpoint(id: EndpointId, roles: Set<net.pocvpn.client.reachability.EndpointRole> = setOf(net.pocvpn.client.reachability.EndpointRole.GATEWAY)) =
        net.pocvpn.client.reachability.EndpointDescriptor(
            id = id,
            roles = roles,
            region = "eu",
            provider = "acme",
            transports = listOf(net.pocvpn.client.reachability.EndpointTransportBinding(net.pocvpn.client.transport.TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
        )

    @Test fun `null eligibleGatewayIds returns the endpoint list unchanged - the pre-B67_7 candidate list`() {
        val endpoints = listOf(endpoint(frankfurt), endpoint(stockholm))
        val result = EntitlementGatewayEligibility.filterEligibleEndpoints(endpoints, null, catalogLookup)
        assertEquals(endpoints, result)
    }

    @Test fun `a non-null eligible set keeps only endpoints mapping to it - ineligible gateway is filtered out`() {
        val endpoints = listOf(endpoint(frankfurt), endpoint(stockholm))
        val result = EntitlementGatewayEligibility.filterEligibleEndpoints(endpoints, setOf(ProductionGatewayId.STOCKHOLM), catalogLookup)
        assertEquals(listOf(endpoint(stockholm)), result)
    }

    @Test fun `a plural eligible set keeps every matching endpoint - Smart Connect still sees more than one candidate`() {
        val endpoints = listOf(endpoint(frankfurt), endpoint(stockholm))
        val result = EntitlementGatewayEligibility.filterEligibleEndpoints(
            endpoints,
            setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            catalogLookup,
        )
        assertEquals(endpoints, result)
    }

    @Test fun `an endpoint the catalog does not recognize as any gateway is never touched by the constraint`() {
        // e.g. a manifest-listed ingress/exit entry - B67.6 eligibility has no defined meaning for a non-gateway role.
        val ingressOnly = endpoint(unknown, roles = setOf(net.pocvpn.client.reachability.EndpointRole.INGRESS))
        val result = EntitlementGatewayEligibility.filterEligibleEndpoints(
            listOf(ingressOnly, endpoint(frankfurt)),
            setOf(ProductionGatewayId.STOCKHOLM), // frankfurt is NOT eligible; ingressOnly is not a gateway at all
            catalogLookup,
        )
        assertEquals(listOf(ingressOnly), result)
    }

    @Test fun `an empty candidate list stays empty regardless of the eligible set`() {
        assertEquals(emptyList<net.pocvpn.client.reachability.EndpointDescriptor>(), EntitlementGatewayEligibility.filterEligibleEndpoints(emptyList(), setOf(ProductionGatewayId.GERMANY), catalogLookup))
    }
}
