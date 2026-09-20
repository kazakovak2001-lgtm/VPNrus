package net.pocvpn.b46harness

/**
 * B46-2P - a distinct research TUN subnet (never the production
 * AmneziaWG/Xray/Shadowsocks TUN address), and a bounded MTU appropriate for
 * the tun2socks/Hysteria2-QUIC bridge (QUIC's own packet overhead vs. a
 * typical path MTU - 1400 leaves headroom under the common ~1500 Ethernet
 * MTU after Hysteria2's WireGuard-adjacent-sized encapsulation, matching the
 * task's own suggested bound; not claimed to be perfectly tuned for every
 * network path).
 *
 * IPv4-only, per the task's own scope: no IPv6 address/route is added here,
 * so (per `VpnService.Builder.allowFamily`'s documented behavior - "if no
 * address, route or DNS server of a specific family is added... all
 * outgoing traffic of that family is blocked") IPv6 is fail-closed/blocked
 * on this interface, not silently bypassed - and no IPv6 validation claim
 * is made anywhere in this slice's documentation.
 */
internal object B46HysteriaTunNetworkConfig {
    const val ADDRESS = "10.203.46.1"
    const val PREFIX_LENGTH = 24
    const val MTU = 1400

    /**
     * The SAME resolvers as production Nova's own
     * `net.pocvpn.client.vpn.config.VpnDnsPolicy.servers` (Cloudflare's
     * public resolvers) - duplicated here, NOT imported, because this
     * harness module deliberately has zero dependency on the `:app` module
     * (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md's "separate
     * module" decision - depending on `:app` would pull its Xray AAR back
     * in and reintroduce the exact gomobile collision this module exists to
     * avoid). If production's list ever changes, this one does not
     * automatically follow - update both by hand.
     */
    val dnsServers: List<String> = listOf("1.1.1.1", "1.0.0.1")

    /** Local SOCKS5 listen address the tun2socks bridge is pointed at - the Hysteria2 child's own local listener. */
    const val LOCAL_SOCKS_HOST = "127.0.0.1"
    const val LOCAL_SOCKS_PORT = 41080
    val localSocksAddr: String get() = "$LOCAL_SOCKS_HOST:$LOCAL_SOCKS_PORT"
}
