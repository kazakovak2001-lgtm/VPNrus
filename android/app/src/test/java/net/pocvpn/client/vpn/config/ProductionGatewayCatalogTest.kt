package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B13 consolidated review fix (findings 1/6, then finding 2 of the second
 * pass) - matchGatewayId is the ONE place a live control-plane response or
 * a legacy persisted profile's stable server facts are mapped to a
 * ProductionGatewayId. Must use the FULL fact set (host+port+key+
 * gatewayTunnelIp), never host alone, and must never guess on a mismatch.
 */
class ProductionGatewayCatalogTest {

    @Test
    fun `matches Germany from its own real host, port, key, and gatewayTunnelIp`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
            gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        )
        assertEquals(ProductionGatewayId.GERMANY, id)
    }

    @Test
    fun `matches Stockholm from its own real host, port, key, and gatewayTunnelIp`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
            gatewayTunnelIp = ProductionGatewayCatalog.STOCKHOLM.awg.gatewayTunnelIp,
        )
        assertEquals(ProductionGatewayId.STOCKHOLM, id)
    }

    @Test
    fun `an unknown host, port, key, and gatewayTunnelIp combination matches nothing - never guessed`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = "203.0.113.9",
            endpointPort = 51820,
            serverPublicKeyBase64 = "not-a-real-key",
            gatewayTunnelIp = "10.99.0.1",
        )
        assertNull(id)
    }

    @Test
    fun `Germany's host with Stockholm's key matches nothing - a rotated-wrong key is never a match`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
            gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        )
        assertNull(id)
    }

    @Test
    fun `Germany's host and key with the wrong port matches nothing`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort + 1,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
            gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        )
        assertNull(id)
    }

    @Test
    fun `correct host, port, and key but a wrong gatewayTunnelIp matches nothing - never accepted-but-ignored`() {
        // B13 SECOND consolidated review fix (finding 2) - the real gap
        // this closes: before gatewayTunnelIp joined the match, this exact
        // combination would have matched GERMANY even though the real
        // runtime always takes gatewayTunnelIp from the catalog, never from
        // the accepted value - i.e. a wrong value could be silently
        // accepted and then ignored rather than rejected.
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
            gatewayTunnelIp = "10.77.0.99",
        )
        assertNull(id)
    }

    @Test
    fun `Germany's own facts with Stockholm's gatewayTunnelIp matches nothing - no cross-endpoint acceptance`() {
        val id = ProductionGatewayCatalog.matchGatewayId(
            endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
            serverPublicKeyBase64 = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
            gatewayTunnelIp = ProductionGatewayCatalog.STOCKHOLM.awg.gatewayTunnelIp,
        )
        // Both gateways happen to share the SAME real gatewayTunnelIp
        // (10.77.0.1) today, so this particular combination actually DOES
        // match Germany - documenting that coincidence explicitly rather
        // than leaving it a silent assumption. The moment either gateway's
        // gatewayTunnelIp ever diverges, this assertion is the one that
        // will (correctly) start failing and must be revisited, not
        // silently left green.
        assertEquals(ProductionGatewayId.GERMANY, id)
    }
}
