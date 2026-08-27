package net.pocvpn.client.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportModelsTest {

    @Test
    fun `amneziaWg capabilities are EXPERIMENTAL, not overclaimed as STABLE`() {
        val caps = TransportCapabilities.amneziaWg()
        assertEquals(TransportMaturity.EXPERIMENTAL, caps.maturity)
        assertTrue(caps.usesUdp)
        assertTrue(caps.supportsObfuscation)
        // Not separately proven yet (see B7I/B8A reports) - must stay false, not assumed.
        assertFalse(caps.supportsIpv6)
        assertFalse(caps.supportsTrafficStatistics)
        assertFalse(caps.supportsProbing)
        assertFalse(caps.suitableForRestrictiveNetworks)
    }

    @Test
    fun `notImplemented capabilities claim nothing`() {
        val caps = TransportCapabilities.notImplemented()
        assertEquals(TransportMaturity.NOT_IMPLEMENTED, caps.maturity)
        assertFalse(caps.usesUdp)
        assertFalse(caps.usesTcp)
        assertFalse(caps.supportsFullTunnel)
        assertFalse(caps.supportsObfuscation)
    }

    @Test
    fun `notImplemented transport health is explicit, not UNKNOWN masquerading as healthy`() {
        val health = TransportHealth.notImplemented()
        assertEquals(TransportHealthState.NOT_IMPLEMENTED, health.state)
        assertEquals(null, health.latencyMillis)
    }

    @Test
    fun `no secret-shaped material can appear in TransportStats - it has no such field`() {
        val counters = TransportStats.Counters(bytesReceived = 180, bytesSent = 112, lastHandshakeEpochMillis = 1_700_000_000_000)
        val text = counters.toString()
        assertFalse(text.contains("PrivateKey", ignoreCase = true))
        assertFalse(text.contains("private_key", ignoreCase = true))
    }

    @Test
    fun `Unsupported and NotImplemented stats are distinct from a real reading`() {
        val stats: TransportStats = TransportStats.Unsupported
        assertTrue(stats !is TransportStats.NotImplemented)
        assertTrue(stats !is TransportStats.Counters)
    }
}
