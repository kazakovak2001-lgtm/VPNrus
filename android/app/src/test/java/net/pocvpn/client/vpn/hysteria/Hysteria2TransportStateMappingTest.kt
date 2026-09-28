package net.pocvpn.client.vpn.hysteria

import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure mapping test - no Context/Intent double needed (mirrors ShadowsocksTransportStateMappingTest exactly). */
class Hysteria2TransportStateMappingTest {

    @Test
    fun `phase mapping is exhaustive and truthful`() {
        assertEquals(TransportState.Disconnected, hysteria2TransportStateFor(Hysteria2RuntimePhase.STOPPED))
        assertEquals(TransportState.Connecting, hysteria2TransportStateFor(Hysteria2RuntimePhase.STARTING))
        assertEquals(TransportState.Connected, hysteria2TransportStateFor(Hysteria2RuntimePhase.RUNNING))
        assertEquals(TransportState.Disconnecting, hysteria2TransportStateFor(Hysteria2RuntimePhase.STOPPING))
        assertTrue(hysteria2TransportStateFor(Hysteria2RuntimePhase.FAILED) is TransportState.Error)
    }
}
