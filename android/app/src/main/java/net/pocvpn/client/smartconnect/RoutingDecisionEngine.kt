package net.pocvpn.client.smartconnect

import net.pocvpn.client.vpn.policy.ClientRoutingPolicy
import net.pocvpn.client.vpn.policy.RoutingMode
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

/**
 * B18 - the largest truthful destination-level distinction the current
 * runtime can actually enforce: a route-prefix check, never per-packet DPI
 * or a hostname/domain lookup. [PROTECTED] is everything else, including
 * every "possible filtering" network condition - see [RoutingDecisionEngine
 * .decideAdaptiveRoute]'s own docs for why a [RestrictionClass] can never
 * turn [PROTECTED] traffic [RouteDecision.Direct].
 */
enum class DestinationClass { LOCAL_PRIVATE, PROTECTED }

/** Typed reasons for diagnostics/tests - see [RoutingDecisionEngine.decideAdaptiveRoute]. */
enum class RoutingReason {
    FULL_VPN_MODE,
    APPS_MODE_DEFAULT_VPN,
    ADAPTIVE_LOCAL_PRIVATE_ELIGIBLE,
    ADAPTIVE_PROTECTED_DEFAULT_VPN,
    NETWORK_UNAVAILABLE,
}

/**
 * B18 - the output of [RoutingDecisionEngine.decideAdaptiveRoute]. [Block]
 * exists for the one case this engine can genuinely assert with no network
 * evidence to route anything over at all ([RestrictionClass.NO_NETWORK]) -
 * it is a diagnostic/typed-reason signal, not itself a VpnService action;
 * VpnController does not gate connect() on it (see that class's own docs).
 */
sealed class RouteDecision {
    data class Direct(val reason: RoutingReason) : RouteDecision()
    data class Vpn(val reason: RoutingReason) : RouteDecision()
    data class Block(val reason: RoutingReason) : RouteDecision()
}

/**
 * Everything [RoutingDecisionEngine.decideAdaptiveRoute] is allowed to look
 * at. [restrictionClass] is the ONE way [RestrictionClassifier]'s output
 * reaches a routing decision (B18 - "wired exactly once") - see that
 * function's own docs for the conservative, non-broadening contract it
 * honors.
 */
data class RoutingContext(
    val routingMode: RoutingMode,
    val destinationClass: DestinationClass,
    val restrictionClass: RestrictionClass,
)

/** What's being routed - only the fields a given ClientRoutingPolicy variant actually needs. */
data class RoutingCandidate(
    val packageName: String? = null,
    val destinationIp: String? = null,
)

object RoutingDecisionEngine {

    /**
     * B18 - the single live authority for DIRECT vs VPN at the destination-
     * route level (architecture principle: never merged with transport/
     * gateway selection - [SmartConnectDecisionEngine]/[AutoGatewaySelector]
     * remain untouched and are never called from here). Deliberately
     * conservative:
     *
     * - [RoutingMode.FULL_VPN] and [RoutingMode.APPS] are byte-for-byte
     *   IDENTICAL here (always [RouteDecision.Vpn]) - APPS mode's
     *   destination-level behavior must never broaden beyond Full VPN's; the
     *   actual per-app split-tunneling APPS mode is named for lives entirely
     *   in [net.pocvpn.client.vpn.policy.AppRoutingPolicy], a layer this
     *   engine never touches (precedence rule: app eligibility decides which
     *   apps' traffic reaches the VPN interface at all; THIS decides, for
     *   traffic that does, whether that destination's route goes direct or
     *   through the tunnel).
     * - [RoutingMode.ADAPTIVE] permits DIRECT only for [DestinationClass
     *   .LOCAL_PRIVATE] (RFC1918/loopback/link-local route prefixes - see
     *   [net.pocvpn.client.vpn.policy.Ipv4RouteExclusion]). Every
     *   [DestinationClass.PROTECTED] destination stays VPN in EVERY
     *   [RestrictionClass] - including [RestrictionClass
     *   .POSSIBLE_UDP_OR_AWG_FILTERING] (a transport/gateway condition,
     *   handled by transport selection/failover, never by routing protected
     *   traffic around the VPN) and [RestrictionClass
     *   .POSSIBLE_HARD_WHITELIST] (routing protected traffic DIRECT here
     *   would BE the forbidden "bypass" - architecture principle 4/10 -
     *   this engine has no notion of "impersonate an allowlisted service"
     *   and must never grow one). [RestrictionClass.UNKNOWN] never widens
     *   DIRECT beyond the user's explicit [RoutingMode] either.
     * - [RestrictionClass.NO_NETWORK] is the one case where restriction
     *   evidence DOES change the outcome (proving this input is genuinely
     *   live, not decorative) - always [RouteDecision.Block], regardless of
     *   mode/destination: no fabricated direct route when there is no
     *   network to route anything over at all.
     */
    fun decideAdaptiveRoute(context: RoutingContext): RouteDecision {
        if (context.restrictionClass == RestrictionClass.NO_NETWORK) {
            return RouteDecision.Block(RoutingReason.NETWORK_UNAVAILABLE)
        }
        return when (context.routingMode) {
            RoutingMode.FULL_VPN -> RouteDecision.Vpn(RoutingReason.FULL_VPN_MODE)
            RoutingMode.APPS -> RouteDecision.Vpn(RoutingReason.APPS_MODE_DEFAULT_VPN)
            RoutingMode.ADAPTIVE -> when (context.destinationClass) {
                DestinationClass.LOCAL_PRIVATE -> RouteDecision.Direct(RoutingReason.ADAPTIVE_LOCAL_PRIVATE_ELIGIBLE)
                DestinationClass.PROTECTED -> RouteDecision.Vpn(RoutingReason.ADAPTIVE_PROTECTED_DEFAULT_VPN)
            }
        }
    }

    /**
     * B18-2 - the ONE shared IPv4 route-list resolver every live transport's
     * VpnService.Builder route construction goes through
     * ([net.pocvpn.client.vpn.VpnController.resolveAdaptiveAllowedIps] for
     * AmneziaWG, [net.pocvpn.client.vpn.xray.buildXrayVpnPlan] for
     * XRAY_REALITY/TLS_TCP) - so ADAPTIVE mode means the EXACT SAME excluded/
     * included IPv4 ranges on every transport, never a second, transport-
     * specific copy of this decision or a duplicate of
     * [net.pocvpn.client.vpn.policy.Ipv4RouteExclusion]'s CIDR math. Built on
     * top of [decideAdaptiveRoute] (no new decision logic here, just turning
     * its [DestinationClass.LOCAL_PRIVATE] verdict into a concrete route
     * list): [fullTunnelRoutes] is returned UNCHANGED for FULL_VPN/APPS, and
     * for ADAPTIVE whenever the evaluated decision is not [RouteDecision
     * .Direct] (e.g. [RestrictionClass.NO_NETWORK] -> [RouteDecision.Block] -
     * never a fabricated direct route). Only for a genuine
     * [RouteDecision.Direct] is [fullTunnelRoutes] replaced with
     * [net.pocvpn.client.vpn.policy.Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES].
     * Callers are responsible for their own IPv6 handling (AWG keeps its
     * "::/0" entry verbatim; Xray/TLS structurally have no IPv6 route field
     * at all - see [net.pocvpn.client.vpn.xray.XrayVpnBuilderPlan]'s own
     * docs) - this function only ever touches the IPv4 route set.
     */
    fun resolveIpv4Routes(fullTunnelRoutes: List<String>, routingMode: RoutingMode, restrictionClass: RestrictionClass): List<String> {
        val decision = decideAdaptiveRoute(RoutingContext(routingMode, DestinationClass.LOCAL_PRIVATE, restrictionClass))
        return if (decision is RouteDecision.Direct) Ipv4RouteExclusionRoutes else fullTunnelRoutes
    }

    private val Ipv4RouteExclusionRoutes: List<String>
        get() = net.pocvpn.client.vpn.policy.Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES

    /** Route-prefix classification ONLY (see [DestinationClass]'s own docs) - never hostname/domain/country heuristics. Unparseable/non-IPv4 input is conservatively [DestinationClass.PROTECTED]. */
    fun classifyDestination(destinationIp: String?): DestinationClass {
        if (destinationIp == null) return DestinationClass.PROTECTED
        val isLocalPrivate = Ipv4RouteExclusionRanges.any { ipInCidr(destinationIp, it) }
        return if (isLocalPrivate) DestinationClass.LOCAL_PRIVATE else DestinationClass.PROTECTED
    }

    private val Ipv4RouteExclusionRanges: List<String>
        get() = net.pocvpn.client.vpn.policy.Ipv4RouteExclusion.LOCAL_PRIVATE_RANGES

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
