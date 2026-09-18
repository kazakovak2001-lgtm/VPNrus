package net.pocvpn.client.vpn.shadowsocks

/**
 * B45B-3 (Phase 5) - the single TUN address/MTU authority for this adapter,
 * mirroring B45ATunNetworkConfig's own "no configuration drift" discipline -
 * both [ShadowsocksVpnService]'s VpnService.Builder.addAddress() call and
 * [ShadowsocksRuntime]'s `--tun-interface-address` sslocal argument read
 * these same constants (the pinned `tun` crate cannot derive its own
 * address/netmask from the received fd - it must be told explicitly, same
 * root cause B45A already documented). Deliberately a different subnet than
 * the debug-only B45A spike's `10.202.45.1/24` - independent, never shared
 * state between the two.
 *
 * IPv4 only (Phase 5): B45A proved IPv4 full-tunnel TCP+UDP only. No IPv6
 * address/route is configured anywhere in this adapter - see
 * XrayVpnBuilderPlan's own docs for why omitting every IPv6 call is itself
 * the fail-closed behavior (VpnService.Builder's documented contract).
 */
internal object ShadowsocksTunConfig {
    const val ADDRESS = "10.202.46.1"
    const val PREFIX_LENGTH = 24
    const val MTU = 1500
    const val CIDR = "$ADDRESS/$PREFIX_LENGTH"
}
