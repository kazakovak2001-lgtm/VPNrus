package net.pocvpn.client.transport

import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B45B-3 (Phase 16, items 18-20 / Phase 15) - guards that the production
 * ShadowsocksTransport/ShadowsocksVpnService adapter shell this slice adds
 * remains genuinely unreachable from real selection: TransportRegistry's
 * defaults() must keep SHADOWSOCKS_2022 at NOT_IMPLEMENTED with no live
 * factory, exactly as before this slice.
 */
class ShadowsocksSelectionSafetyTest {

    @Test
    fun `SHADOWSOCKS_2022 stays NOT_IMPLEMENTED in the default registry`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        val descriptor = registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, descriptor?.status)
    }

    @Test
    fun `createTransport returns null for SHADOWSOCKS_2022 - no live factory`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        assertNull(registry.createTransport(TransportKind.SHADOWSOCKS_2022))
    }

    @Test
    fun `available() never includes SHADOWSOCKS_2022`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() }
        assertEquals(emptyList<TransportKind>(), registry.available().map { it.kind }.filter { it == TransportKind.SHADOWSOCKS_2022 })
    }
}
