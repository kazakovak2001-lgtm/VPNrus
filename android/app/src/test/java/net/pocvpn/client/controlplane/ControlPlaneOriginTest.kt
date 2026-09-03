package net.pocvpn.client.controlplane

import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ControlPlaneOriginTest {

    @Test
    fun `origins for a gateway come from ProductionGatewayCatalog - the compiled trusted configuration - never an empty or user-suppliable list`() {
        val germany = ControlPlaneOriginSetBuilder.forGateway(ProductionGatewayId.GERMANY)
        assertTrue(germany.isNotEmpty())
        assertTrue(germany.all { it.gatewayId == ProductionGatewayId.GERMANY })
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointHost, germany.first().host)
    }

    @Test
    fun `origins for a different gateway never leak the other gateway's host`() {
        val germany = ControlPlaneOriginSetBuilder.forGateway(ProductionGatewayId.GERMANY)
        val stockholm = ControlPlaneOriginSetBuilder.forGateway(ProductionGatewayId.STOCKHOLM)
        assertTrue(germany.none { it.host == ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost })
        assertTrue(stockholm.none { it.host == ProductionGatewayCatalog.GERMANY.awg.endpointHost })
    }

    @Test
    fun `classifyControlPlaneIoException maps well-known exception types to the closed taxonomy`() {
        assertEquals(ControlPlaneFailureReason.DNS_RESOLUTION_FAILED, classifyControlPlaneIoException(java.net.UnknownHostException()))
        assertEquals(ControlPlaneFailureReason.CONNECT_TIMEOUT, classifyControlPlaneIoException(java.net.SocketTimeoutException()))
        assertEquals(ControlPlaneFailureReason.TLS_TRUST_FAILED, classifyControlPlaneIoException(javax.net.ssl.SSLHandshakeException("x")))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyControlPlaneIoException(java.io.IOException("connection refused")))
    }

    @Test
    fun `classifyNetworkErrorMessage classifies ProvisioningClient's own deterministic exception-class-name prefix, never arbitrary text`() {
        assertEquals(ControlPlaneFailureReason.DNS_RESOLUTION_FAILED, classifyNetworkErrorMessage("UnknownHostException: nope"))
        assertEquals(ControlPlaneFailureReason.CONNECT_TIMEOUT, classifyNetworkErrorMessage("SocketTimeoutException: timed out"))
        assertEquals(ControlPlaneFailureReason.TLS_TRUST_FAILED, classifyNetworkErrorMessage("SSLHandshakeException: cert"))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyNetworkErrorMessage("IOException: connection refused"))
        assertEquals(ControlPlaneFailureReason.HTTP_UNAVAILABLE, classifyNetworkErrorMessage("anything else entirely"))
    }
}
