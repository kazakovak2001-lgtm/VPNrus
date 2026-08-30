package net.pocvpn.client.vpn.xray

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B13 (2026-08-30 correctness audit item 5) - pure-function proof for
 * [parseEndpointIdExtra] (NovaXrayVpnService.kt), mirroring the same
 * "directly unit-testable, independent of any Context/Intent double"
 * reasoning [xrayTransportStateFor]'s own file already establishes.
 */
class NovaXrayVpnServiceEndpointParsingTest {

    @Test
    fun `a real endpoint id extra is parsed verbatim`() {
        assertEquals(EndpointId("gateway-b"), parseEndpointIdExtra("gateway-b"))
    }

    @Test
    fun `an absent extra - every pre-B13 caller - fails safe to the production endpoint`() {
        assertEquals(EndpointId(ProductionGateway.ID), parseEndpointIdExtra(null))
    }

    @Test
    fun `a blank extra fails safe to the production endpoint, same as absent`() {
        assertEquals(EndpointId(ProductionGateway.ID), parseEndpointIdExtra(""))
        assertEquals(EndpointId(ProductionGateway.ID), parseEndpointIdExtra("   "))
    }
}
