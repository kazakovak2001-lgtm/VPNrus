package net.pocvpn.client.vpn.xray

import net.pocvpn.client.vpn.DataPlaneConfirmation
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B-WL7 M1 - only a positive `:xray` answer for a session that is STILL the
 * Started one confirms the tunnel; everything else keeps the counters' verdict.
 */
class XrayTunnelConfirmationTest {

    @Test
    fun `a positive answer for the same still-Started session confirms`() {
        assertEquals(DataPlaneConfirmation.CONFIRMED, XrayProcessBridge.tunnelConfirmationFor(answer = true, stillStartedSameSession = true))
    }

    @Test
    fun `a positive answer after the session changed does not confirm`() {
        assertEquals(DataPlaneConfirmation.NOT_CONFIRMED, XrayProcessBridge.tunnelConfirmationFor(answer = true, stillStartedSameSession = false))
    }

    @Test
    fun `a negative answer or no answer does not confirm`() {
        assertEquals(DataPlaneConfirmation.NOT_CONFIRMED, XrayProcessBridge.tunnelConfirmationFor(answer = false, stillStartedSameSession = true))
        assertEquals(DataPlaneConfirmation.NOT_CONFIRMED, XrayProcessBridge.tunnelConfirmationFor(answer = null, stillStartedSameSession = true))
    }
}
