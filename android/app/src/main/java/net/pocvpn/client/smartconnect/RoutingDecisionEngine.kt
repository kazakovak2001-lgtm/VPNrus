package net.pocvpn.client.smartconnect

import net.pocvpn.client.vpn.policy.ClientRoutingPolicy
import java.net.Inet4Address
import java.net.InetAddress

/**
 * "Should this traffic use the VPN at all?" - deliberately separate from
 * "which VPN transport should carry it?" (SmartConnectDecisionEngine).
 * Pure function over the existing ClientRoutingPolicy model; does not touch
 * VpnService, does not do deep packet inspection.
 */
enum class RoutingDecision {
    DIRECT,
    VPN,
}

/** What's being routed - only the fields a given ClientRoutingPolicy variant actually needs. */
data class RoutingCandidate(
    val packageName: String? = null,
    val destinationIp: String? = null,
)

object RoutingDecisionEngine {

    fun decide(candidate: RoutingCandidate, policy: ClientRoutingPolicy): RoutingDecision = when (policy) {
        is ClientRoutingPolicy.FullTunnel -> RoutingDecision.VPN

        is ClientRoutingPolicy.VpnAppAllowlist ->
            if (candidate.packageName in policy.allowedPackages) RoutingDecision.VPN else RoutingDecision.DIRECT

        is ClientRoutingPolicy.DirectAppList ->
            if (candidate.packageName in policy.bypassPackages) RoutingDecision.DIRECT else RoutingDecision.VPN

        is ClientRoutingPolicy.IpCidrPolicy -> decideByCidr(candidate.destinationIp, policy)
    }

    private fun decideByCidr(destinationIp: String?, policy: ClientRoutingPolicy.IpCidrPolicy): RoutingDecision {
        if (destinationIp == null) return RoutingDecision.VPN // unspecified destination: fail-safe toward the VPN, not the open network
        if (policy.outsideVpn.any { ipInCidr(destinationIp, it) }) return RoutingDecision.DIRECT
        if (policy.throughVpn.any { ipInCidr(destinationIp, it) }) return RoutingDecision.VPN
        return RoutingDecision.VPN // not explicitly listed either way: fail-safe toward the VPN
    }

    /** IPv4-only, matching the current POC-01 addressing scope (see gateway/README.md). */
    private fun ipInCidr(ip: String, cidr: String): Boolean {
        val (network, prefixStr) = cidr.split("/", limit = 2).let {
            if (it.size == 2) it[0] to it[1] else return false
        }
        val prefix = prefixStr.toIntOrNull() ?: return false
        val ipAddr = parseIpv4(ip) ?: return false
        val netAddr = parseIpv4(network) ?: return false
        if (prefix == 0) return true
        val mask = -1 shl (32 - prefix)
        return (ipAddr and mask) == (netAddr and mask)
    }

    private fun parseIpv4(ip: String): Int? {
        val address = runCatching { InetAddress.getByName(ip) }.getOrNull() as? Inet4Address ?: return null
        val bytes = address.address
        return (bytes[0].toInt() and 0xFF shl 24) or
            (bytes[1].toInt() and 0xFF shl 16) or
            (bytes[2].toInt() and 0xFF shl 8) or
            (bytes[3].toInt() and 0xFF)
    }
}
