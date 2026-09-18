package net.pocvpn.client.transport

import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B45B-3 (Phase 16, items 18-20 / Phase 15) - guards that TransportRegistry's
 * static defaults() helper (a legacy Phase-2A fixture, distinct from the real
 * per-endpoint construction path - MainViewModel.buildTransportRegistry(endpointId) -
 * that B45B-4 wires SHADOWSOCKS_2022 selection into) keeps SHADOWSOCKS_2022 at
 * NOT_IMPLEMENTED with no live factory. B45B-4's own tests
 * (MainViewModelShadowsocksSelectionTest) cover the real selection path.
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
