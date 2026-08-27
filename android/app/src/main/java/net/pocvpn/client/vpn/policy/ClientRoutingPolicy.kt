package net.pocvpn.client.vpn.policy

/**
 * Model-only, transport-agnostic routing policy. Nothing here is wired into
 * AmneziaWgTransport/VpnController yet - this is the foundation Smart
 * Connect will later use to choose between DIRECT/AWG/other transports per
 * app or destination. No deep packet inspection, domain interception, or
 * censorship-bypass logic - that is explicitly out of scope here.
 *
 * IMPORTANT: VpnService.addAllowedApplication()/addDisallowedApplication()
 * only decide which apps' traffic is ROUTED THROUGH the VPN interface.
 * Unlisted apps are NOT blocked from the internet - they simply use the
 * normal underlying network, exactly as if the VPN were not running. Do not
 * represent VPN_APP_ALLOWLIST or DIRECT_APP_LIST as a way to block traffic.
 */
sealed class ClientRoutingPolicy {

    /** All eligible traffic routes through the VPN. The POC-01 default. */
    object FullTunnel : ClientRoutingPolicy()

    /**
     * Only [allowedPackages] route through the VPN via addAllowedApplication().
     * Every other app uses the underlying network directly - NOT blocked.
     */
    data class VpnAppAllowlist(val allowedPackages: Set<String>) : ClientRoutingPolicy()

    /**
     * [bypassPackages] route via addDisallowedApplication() (use the underlying
     * network directly); every other app's eligible traffic uses the VPN.
     */
    data class DirectAppList(val bypassPackages: Set<String>) : ClientRoutingPolicy()

    /** Explicit IP/CIDR ranges routed through vs outside the VPN. */
    data class IpCidrPolicy(val throughVpn: List<String>, val outsideVpn: List<String>) : ClientRoutingPolicy()
}

/**
 * Traffic outside the allowed set must have NO usable internet path. This is
 * NOT achievable via VpnService alone (see ClientRoutingPolicy's warning) -
 * it requires Android's own "Always-on VPN" + "Block connections without
 * VPN" system setting, which the app can only link the user to, not enable
 * silently on an unmanaged device. Deliberately kept as a separate type from
 * ClientRoutingPolicy so the two are never confused or conflated.
 */
enum class StrictNetworkAllowlistRequirement {
    REQUIRES_ANDROID_LOCKDOWN_MODE,
}
