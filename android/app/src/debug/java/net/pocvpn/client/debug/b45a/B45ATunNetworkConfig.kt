package net.pocvpn.client.debug.b45a

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * The SINGLE debug TUN network configuration authority for this spike (see
 * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 29's own "no configuration
 * drift" requirement) - both [B45ASpikeVpnService]'s
 * `VpnService.Builder.addAddress()`/`addRoute()` calls (the Android-side,
 * OS-level interface configuration) AND [B45ARuntime]'s
 * `--tun-interface-address` CLI argument to real `sslocal` (the Rust-side
 * `tun` crate's OWN mirror of that same address/netmask, needed because -
 * round 4's own root-cause finding - the pinned `tun` crate's Android
 * device implementation cannot derive `address()`/`netmask()` from the
 * received fd itself; it only returns whatever was explicitly configured)
 * read from these same constants. There is exactly one `10.202.45.1/24`
 * literal in this codebase, not two independently-hardcoded ones.
 *
 * `CIDR` MUST match `ADDRESS`/`PREFIX_LENGTH` exactly, since real `sslocal`
 * parses it as a single `IpNet` value
 * (`crates/shadowsocks/src/vparser/mod.rs`'s `parse_ipnet` at the pinned
 * commit - "should be a CIDR address like 10.1.2.3/24") and splits it back
 * into address+netmask itself
 * (`crates/shadowsocks-service/src/local/tun/mod.rs`'s
 * `TunBuilder::address(addr: IpNet)`:
 * `tun_config.address(addr.addr()).netmask(addr.netmask())`).
 */
internal object B45ATunNetworkConfig {
    const val ADDRESS = "10.202.45.1"
    const val PREFIX_LENGTH = 24
    const val ROUTE = "10.202.45.0"
    const val MTU = 1500

    /** `"$ADDRESS/$PREFIX_LENGTH"` - the exact CIDR string real `sslocal`'s `--tun-interface-address` flag expects. */
    const val CIDR = "$ADDRESS/$PREFIX_LENGTH"

    /**
     * Round 6 (data-plane validation) - IPv4 default route, added to the
     * `VpnService.Builder` ONLY when a real (non-fallback) data-plane
     * target is configured via `B45ADataPlaneConfig`/`b45a-dataplane.properties`
     * (see [B45ASpikeVpnService]'s own call site). Rounds 1-5's own narrow
     * [ROUTE]-only config (this spike's original, deliberate "cannot
     * hijack real device traffic" safety property - see
     * docs/B45A_SHADOWSOCKS_RUST_SPIKE.md Section 19.4) is preserved
     * exactly as before for every checkout WITHOUT that properties file -
     * this default route exists only to let real application traffic
     * reach the TUN so Q4/Q5 can be tested at all; it is never added
     * unconditionally. IPv6 is deliberately still never routed (no IPv6
     * address/route added anywhere in this spike) - IPv6-capable
     * requests continue to bypass the tunnel entirely, a known limitation
     * recorded for the direct-bypass check, not a defect.
     */
    const val DEFAULT_ROUTE = "0.0.0.0"
    const val DEFAULT_ROUTE_PREFIX = 0
}
