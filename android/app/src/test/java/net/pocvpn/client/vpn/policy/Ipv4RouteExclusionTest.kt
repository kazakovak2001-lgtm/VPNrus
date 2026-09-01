package net.pocvpn.client.vpn.policy

import java.math.BigInteger
import java.net.Inet4Address
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B18 - proves Ipv4RouteExclusion.computeAllowedRoutes is a genuinely correct
 * "0.0.0.0/0 minus the excluded ranges", not merely plausible-looking output:
 * total coverage sums to exactly the complement's size, no two output blocks
 * overlap, every excluded address is absent, and addresses just outside an
 * excluded range are present.
 */
class Ipv4RouteExclusionTest {

    private fun blockSize(prefix: Int): BigInteger = BigInteger.TWO.pow(32 - prefix)

    private fun parse(cidr: String): Pair<BigInteger, Int> {
        val (ip, prefixStr) = cidr.split("/", limit = 2)
        val bytes = (InetAddress.getByName(ip) as Inet4Address).address
        var value = BigInteger.ZERO
        for (b in bytes) value = value.shiftLeft(8).or(BigInteger.valueOf((b.toInt() and 0xFF).toLong()))
        return value to prefixStr.toInt()
    }

    private fun contains(cidr: String, ip: String): Boolean {
        val (network, prefix) = parse(cidr)
        val (addr, _) = parse("$ip/32")
        val size = blockSize(prefix)
        return addr >= network && addr < network + size
    }

    @Test
    fun `output never overlaps and never re-includes an excluded range`() {
        val excluded = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
        val routes = Ipv4RouteExclusion.computeAllowedRoutes(excluded)

        val ranges = routes.map(::parse)
        for (i in ranges.indices) {
            for (j in ranges.indices) {
                if (i == j) continue
                val (netI, prefixI) = ranges[i]
                val (netJ, prefixJ) = ranges[j]
                val endI = netI + blockSize(prefixI) - BigInteger.ONE
                val endJ = netJ + blockSize(prefixJ) - BigInteger.ONE
                val overlap = netI <= endJ && endI >= netJ
                assertFalse("routes $i and $j overlap: ${routes[i]} / ${routes[j]}", overlap)
            }
        }
    }

    @Test
    fun `total covered addresses equal the whole IPv4 space minus every excluded range`() {
        val excluded = listOf("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16")
        val routes = Ipv4RouteExclusion.computeAllowedRoutes(excluded)

        val totalCovered = routes.sumOf { blockSize(it.substringAfter("/").toInt()) }
        val totalExcluded = excluded.sumOf { blockSize(it.substringAfter("/").toInt()) }
        val wholeSpace = BigInteger.TWO.pow(32)

        assertEquals(wholeSpace, totalCovered + totalExcluded)
    }

    @Test
    fun `a private LAN address is not covered by any output route`() {
        val routes = Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES
        assertFalse(routes.any { contains(it, "192.168.1.42") })
        assertFalse(routes.any { contains(it, "10.5.5.5") })
        assertFalse(routes.any { contains(it, "172.20.0.1") })
        assertFalse(routes.any { contains(it, "127.0.0.1") })
        assertFalse(routes.any { contains(it, "169.254.1.1") })
    }

    @Test
    fun `a public destination is covered by exactly one output route`() {
        val routes = Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES
        assertTrue(routes.any { contains(it, "8.8.8.8") })
        assertTrue(routes.any { contains(it, "1.1.1.1") })
        assertEquals(1, routes.count { contains(it, "8.8.8.8") })
    }

    @Test
    fun `an address just outside 172_16_0_0-12 is covered`() {
        val routes = Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES
        assertTrue(routes.any { contains(it, "172.15.255.255") })
        assertTrue(routes.any { contains(it, "172.32.0.0") })
    }

    @Test
    fun `no exclusions yields exactly 0_0_0_0-0`() {
        assertEquals(listOf("0.0.0.0/0"), Ipv4RouteExclusion.computeAllowedRoutes(emptyList()))
    }
}
