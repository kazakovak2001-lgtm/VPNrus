package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B13 consolidated review fix (findings 1/6) - matchGatewayId is the ONE
 * place a live control-plane response's stable server facts are mapped to a
 * ProductionGatewayId. Must use the FULL fact set (host+port+key), never
 * host alone, and must never guess on a mismatch.
 */
class ProductionGatewayCatalogTest {

    @Test
    fun `matches Germany from its own real host, port, and key`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        )
        assertEquals(ProductionGatewayId.GERMANY, id)
    }

    @Test
    fun `matches Stockholm from its own real host, port, and key`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
        )
        assertEquals(ProductionGatewayId.STOCKHOLM, id)
    }

    @Test
    fun `an unknown host, port, and key combination matches nothing - never guessed`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = "203.0.113.9",
            endpointPort = 51820,
            serverPublicKeyBase64 = "not-a-real-key",
        )
        assertNull(id)
    }

    @Test
    fun `Germany's host with Stockholm's key matches nothing - a rotated-wrong key is never a match`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
        )
        assertNull(id)
    }

    @Test
    fun `Germany's host and key with the wrong port matches nothing`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort + 1,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        )
        assertNull(id)
    }
}
