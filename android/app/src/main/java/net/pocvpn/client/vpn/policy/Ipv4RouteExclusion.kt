package net.pocvpn.client.vpn.policy

import java.net.Inet4Address
import java.net.InetAddress

/**
 * B18 - pure IPv4 CIDR-subtraction math: "every route EXCEPT these ranges",
 * expressed as its own minimal set of CIDR blocks. This is the largest
 * truthful decision boundary Adaptive Direct Routing enforces today (see
 * RoutingDecisionEngine's own docs) - a ROUTE-PREFIX-level decision, never
 * per-packet/per-hostname DPI. Recursive interval subtraction (halve the
 * current block until it either fully avoids or is fully covered by an
 * excluded range) - standard, provably-correct, and cheap for the small
 * excluded set this file actually uses (RFC1918 + loopback + link-local, see
 * [LOCAL_PRIVATE_RANGES]), never a hand-maintained literal list that could
 * silently drift out of sync with the excluded ranges.
 */
object Ipv4RouteExclusion {

    /** RFC1918 private ranges + loopback + link-local - the ONLY ranges Adaptive Direct Routing ever excludes from the VPN's IPv4 route set. */
    val LOCAL_PRIVATE_RANGES: List<String> = listOf(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )

    /** The route set a FULL_VPN/APPS-mode IPv4 allowedIps entry of "0.0.0.0/0" would otherwise use, minus [LOCAL_PRIVATE_RANGES]. Computed once - the input is fixed, never per-device/per-network data. */
    val ADAPTIVE_DIRECT_IPV4_ROUTES: List<String> by lazy { computeAllowedRoutes(LOCAL_PRIVATE_RANGES) }

    /** Pure and deterministic - the whole IPv4 address space (0.0.0.0/0) minus every range in [excluded], as a minimal covering set of CIDR blocks. */
    fun computeAllowedRoutes(excluded: List<String>): List<String> {
        val ranges = excluded.map(::parseCidr)
        val result = mutableListOf<String>()
        subtract(0L, 0, ranges, result)
        return result
    }

    private fun subtract(network: Long, prefix: Int, excluded: List<Pair<Long, Int>>, out: MutableList<String>) {
        val blockSize = 1L shl (32 - prefix)
        val blockEnd = network + blockSize - 1
        if (excluded.any { (exNet, exPrefix) -> network >= exNet && blockEnd <= exclusiveEnd(exNet, exPrefix) }) return
        val intersects = excluded.any { (exNet, exPrefix) -> network <= exclusiveEnd(exNet, exPrefix) && blockEnd >= exNet }
        if (!intersects) {
            out.add(cidrString(network, prefix))
            return
        }
        // prefix < 32 is guaranteed here: every LOCAL_PRIVATE_RANGES entry has
        // prefix <= 16, so a block can only "intersect but not be fully
        // covered" while its own prefix is still coarser than the excluded
        // range's - it always fully resolves (covered or clear) well before
        // reaching /32.
        val half = blockSize / 2
        subtract(network, prefix + 1, excluded, out)
        subtract(network + half, prefix + 1, excluded, out)
    }

    private fun exclusiveEnd(network: Long, prefix: Int): Long = network + (1L shl (32 - prefix)) - 1

    private fun parseCidr(cidr: String): Pair<Long, Int> {
        val (network, prefixStr) = cidr.split("/", limit = 2)
        val prefix = prefixStr.toInt()
        return parseIpv4(network) to prefix
    }

    private fun parseIpv4(ip: String): Long {
        val address = InetAddress.getByName(ip) as Inet4Address
        val bytes = address.address
        return ((bytes[0].toLong() and 0xFF) shl 24) or
            ((bytes[1].toLong() and 0xFF) shl 16) or
            ((bytes[2].toLong() and 0xFF) shl 8) or
            (bytes[3].toLong() and 0xFF)
    }

    private fun cidrString(network: Long, prefix: Int): String {
        val a = (network shr 24) and 0xFF
        val b = (network shr 16) and 0xFF
        val c = (network shr 8) and 0xFF
        val d = network and 0xFF
        return "$a.$b.$c.$d/$prefix"
    }
}
