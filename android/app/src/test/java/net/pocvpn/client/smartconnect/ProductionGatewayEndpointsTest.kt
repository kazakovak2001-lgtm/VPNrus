package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProductionGatewayEndpointsTest {

    @Test
    fun `AWG is always present regardless of Xray availability`() {
        val descriptor = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.GERMANY, xrayAvailable = false, xrayTlsAvailable = false)
        assertTrue(descriptor.supports(TransportKind.AMNEZIA_WG))
        assertFalse(descriptor.supports(TransportKind.XRAY_REALITY))
        assertFalse(descriptor.supports(TransportKind.TLS_TCP))
    }

    @Test
    fun `Xray REALITY and TLS appear only when their own availability flag is true`() {
        val descriptor = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.STOCKHOLM, xrayAvailable = true, xrayTlsAvailable = true)
        assertTrue(descriptor.supports(TransportKind.AMNEZIA_WG))
        assertTrue(descriptor.supports(TransportKind.XRAY_REALITY))
        assertTrue(descriptor.supports(TransportKind.TLS_TCP))
    }

    @Test
    fun `id matches the gateway's own endpointId - never a fabricated identity`() {
        val descriptor = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.STOCKHOLM, xrayAvailable = false, xrayTlsAvailable = false)
        assertEquals(ProductionGatewayCatalog.STOCKHOLM.endpointId, descriptor.id)
    }

    @Test
    fun `roles mark this endpoint as both GATEWAY and EXIT - today's real Direct-only shape`() {
        val descriptor = ProductionGatewayEndpoints.descriptorFor(ProductionGatewayCatalog.GERMANY, xrayAvailable = false, xrayTlsAvailable = false)
        assertEquals(setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), descriptor.roles)
    }
}
