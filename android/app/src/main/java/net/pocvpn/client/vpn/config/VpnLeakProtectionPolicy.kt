package net.pocvpn.client.vpn.config

/**
 * B8F - the one canonical, LOCAL (never provisioning-response-owned) source
 * for the VPN's DNS resolvers. No activation/provisioning response carries
 * DNS - see gateway/api/handler.py's _handle_activate payload (client_tunnel_ip/
 * gateway_public_key/gateway_tunnel_ip/endpoint_host/endpoint_port only) and
 * PersistedProfile (same five fields) - DNS ownership stays entirely on this
 * client, as a policy decision independent of which device/activation this is.
 *
 * Applied in exactly ONE place - DefaultGatewayConfigurationRepository.get() -
 * which every profile source (BuildConfigGatewaySource dev fallback,
 * ProvisionedProfileStore-restored, or a freshly activateDevice()-provisioned
 * MutableGatewayConfigSource override) already converges through before
 * VpnController ever builds a TransportConfig. That convergence is what makes
 * this apply uniformly regardless of profile source, with no per-source
 * wiring and no second place this list could drift out of sync with.
 */
object VpnDnsPolicy {
    /**
     * Cloudflare's privacy-respecting public resolvers - reachable through
     * the full IPv4 tunnel (0.0.0.0/0, see AwgPeer's own default) once
     * connected. Forwarded into the AmneziaWG interface config completely
     * unchanged by AwgConfigMapper's existing
     * `awg.dnsServers.forEach { iface.addDnsServer(it) }` - no new parsing
     * or hardcoding is introduced at that layer.
     */
    val servers: List<String> = listOf("1.1.1.1", "1.0.0.1")
}

/**
 * B8F - describes what happens to IPv6 traffic once connected. Diagnostics-
 * only metadata, NEVER a routing switch: AllowedIps always keeps ::/0 (see
 * AwgPeer's own default and DefaultGatewayConfigurationRepository
 * .resolveAllowedIps) regardless of this value. Removing ::/0 to "fix" a
 * FAIL_CLOSED reading would let IPv6 bypass the tunnel entirely onto the
 * phone's direct ISP/Wi-Fi path - exactly the leak this policy exists to
 * prevent - so nothing in this file is wired to ever change AllowedIps.
 *
 * FAIL_CLOSED: IPv6 destinations are captured into the tunnel's own routing
 * table (an actual ::/0 route on the Android VpnService interface - see
 * android.net.VpnService.Builder.allowFamily's own javadoc: "if no address,
 * route or DNS server of a specific family is added to this VPN, then all
 * outgoing traffic of that family is blocked" - a route of that family IS
 * present here) but this gateway does not yet forward IPv6 anywhere, so
 * that traffic simply fails/times out inside the tunnel - unavailable,
 * never leaked around it onto the underlying network.
 *
 * Becomes TUNNELED only once the gateway actually forwards IPv6 end to end
 * (out of scope for B8F).
 */
enum class Ipv6LeakPolicy { TUNNELED, FAIL_CLOSED }

object VpnIpv6Policy {
    val current: Ipv6LeakPolicy = Ipv6LeakPolicy.FAIL_CLOSED
}
