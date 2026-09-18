package net.pocvpn.client.vpn.shadowsocks

import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure mapping test - no Context/Intent double needed (same convention as VlessTlsTransport's xrayTransportStateFor tests). */
class ShadowsocksTransportStateMappingTest {

    @Test
    fun `phase mapping is exhaustive and truthful`() {
        assertEquals(TransportState.Disconnected, shadowsocksTransportStateFor(ShadowsocksRuntimePhase.STOPPED))
        assertEquals(TransportState.Connecting, shadowsocksTransportStateFor(ShadowsocksRuntimePhase.STARTING))
        assertEquals(TransportState.Connected, shadowsocksTransportStateFor(ShadowsocksRuntimePhase.RUNNING))
        assertEquals(TransportState.Disconnecting, shadowsocksTransportStateFor(ShadowsocksRuntimePhase.STOPPING))
        assertTrue(shadowsocksTransportStateFor(ShadowsocksRuntimePhase.FAILED) is TransportState.Error)
    }
}
