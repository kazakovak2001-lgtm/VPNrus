package net.pocvpn.client.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B45B-1 - types + metadata only. No runtime behavior is exercised here. */
class Shadowsocks2022TypesTest {

    @Test
    fun `TransportKind contains SHADOWSOCKS_2022`() {
        assertTrue(TransportKind.entries.contains(TransportKind.SHADOWSOCKS_2022))
    }

    @Test
    fun `shadowsocks2022 capabilities truthfully reflect only what B45A physically proved`() {
        val caps = TransportCapabilities.shadowsocks2022()
        // Physically proven by B45A (real TCP+UDP through a real VpnService TUN).
        assertTrue(caps.usesTcp)
        assertTrue(caps.usesUdp)
        assertTrue(caps.supportsFullTunnel)
    }

    @Test
    fun `shadowsocks2022 capabilities do not claim roaming or handover support`() {
        // Q7 (Wi-Fi/cellular handover) remains BLOCKED/deferred/UNVERIFIED - must never be true here.
        assertFalse(TransportCapabilities.shadowsocks2022().supportsRoaming)
    }

    @Test
    fun `shadowsocks2022 capabilities do not claim censorship-resistance`() {
        assertFalse(TransportCapabilities.shadowsocks2022().suitableForRestrictiveNetworks)
    }

    @Test
    fun `shadowsocks2022 capabilities do not claim obfuscation, split routing, IPv6, stats, or probing`() {
        val caps = TransportCapabilities.shadowsocks2022()
        assertFalse(caps.supportsObfuscation)
        assertFalse(caps.supportsSplitRouting)
        assertFalse(caps.supportsIpv6)
        assertFalse(caps.supportsTrafficStatistics)
        assertFalse(caps.supportsProbing)
    }

    @Test
    fun `shadowsocks2022 capabilities maturity is NOT_IMPLEMENTED - no adapter code exists yet`() {
        assertEquals(TransportMaturity.NOT_IMPLEMENTED, TransportCapabilities.shadowsocks2022().maturity)
    }

    @Test
    fun `existing amneziaWg capabilities are unchanged`() {
        // Confirms adding a new TransportKind/capability factory didn't perturb an existing one.
        val caps = TransportCapabilities.amneziaWg()
        assertTrue(caps.usesUdp)
        assertFalse(caps.usesTcp)
        assertEquals(TransportMaturity.EXPERIMENTAL, caps.maturity)
    }
}
