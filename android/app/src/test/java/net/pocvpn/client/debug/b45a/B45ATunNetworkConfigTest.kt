package net.pocvpn.client.debug.b45a

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45A - SPIKE ONLY. Guards [B45ATunNetworkConfig.CIDR]'s format and its
 * derivation from [B45ATunNetworkConfig.ADDRESS]/[B45ATunNetworkConfig.PREFIX_LENGTH] -
 * real `sslocal`'s `--tun-interface-address` (round 5, see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 29) parses this as a single
 * `IpNet` value and requires exactly this `<address>/<prefix>` shape
 * (`vparser::parse_ipnet` at the pinned commit: "should be a CIDR address
 * like 10.1.2.3/24").
 */
class B45ATunNetworkConfigTest {

    @Test
    fun `CIDR is exactly address slash prefix, never independently hardcoded`() {
        assertEquals(
            "${B45ATunNetworkConfig.ADDRESS}/${B45ATunNetworkConfig.PREFIX_LENGTH}",
            B45ATunNetworkConfig.CIDR,
        )
    }

    @Test
    fun `CIDR matches the exact literal value both callers currently expect`() {
        assertEquals("10.202.45.1/24", B45ATunNetworkConfig.CIDR)
    }

    @Test
    fun `prefix length is preserved as the CIDR suffix`() {
        assertTrue(B45ATunNetworkConfig.CIDR.endsWith("/${B45ATunNetworkConfig.PREFIX_LENGTH}"))
    }

    @Test
    fun `route stays within the same subnet as the address`() {
        // Both must share the same /24 network for addRoute()'s own subnet to make sense.
        val addressPrefix = B45ATunNetworkConfig.ADDRESS.substringBeforeLast('.')
        val routePrefix = B45ATunNetworkConfig.ROUTE.substringBeforeLast('.')
        assertEquals(addressPrefix, routePrefix)
    }
}
