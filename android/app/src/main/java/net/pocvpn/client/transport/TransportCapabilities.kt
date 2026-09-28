package net.pocvpn.client.transport

/** How far along a transport's implementation actually is - never inflated. */
enum class TransportMaturity {
    NOT_IMPLEMENTED,
    EXPERIMENTAL,
    STABLE,
}

/**
 * Transport-agnostic, typed facts about a protocol - what Smart Connect can
 * use to reason about which transport fits current network conditions,
 * without knowing anything protocol-specific. Every field here must reflect
 * something actually true/implemented; a NOT_IMPLEMENTED transport's
 * capabilities describe its intended future design, not a working feature.
 */
data class TransportCapabilities(
    val usesUdp: Boolean,
    val usesTcp: Boolean,
    val supportsPort443: Boolean,
    val supportsObfuscation: Boolean,
    val suitableForRestrictiveNetworks: Boolean,
    val supportsRoaming: Boolean,
    val supportsFullTunnel: Boolean,
    val supportsSplitRouting: Boolean,
    val supportsIpv6: Boolean,
    val supportsTrafficStatistics: Boolean,
    val supportsProbing: Boolean,
    val maturity: TransportMaturity,
) {
    companion object {
        /**
         * AmneziaWG 3.1 as actually implemented in this app as of B8A: real
         * UDP handshake proven locally (WSL2), full-tunnel + narrow AllowedIPs
         * both exercised, obfuscation profile (Jc/Jmin/Jmax/H1-4) real and
         * pinned. IPv6/roaming/split-routing/traffic-stats/probing are NOT
         * separately proven yet (see B8A/B7I reports) - kept false, not
         * assumed, until each has its own verified evidence.
         */
        fun amneziaWg(): TransportCapabilities = TransportCapabilities(
            usesUdp = true,
            usesTcp = false,
            supportsPort443 = false,
            supportsObfuscation = true,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = true,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /**
         * B8K1B - VlessRealityTransport/NovaXrayVpnService as an isolated
         * adapter shell: real code exists (config validation/rendering, a
         * real VpnService establishing a real TUN and starting the pinned
         * Xray core, self-UID exclusion) but has zero physical-device
         * evidence yet (see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md §12/§13) and
         * is not registered AVAILABLE in TransportRegistry - this value
         * describes only what the adapter code itself does, never a claim
         * about Smart Connect eligibility (that gate is TransportRegistry's
         * NOT_IMPLEMENTED status, unaffected by this factory existing).
         * supportsSplitRouting is false: this slice is ALL_APPS only, no
         * BYPASS_SELECTED/VPN_ONLY_SELECTED parity yet. supportsIpv6 is
         * false: no IPv6 address/route is ever configured (fail-closed by
         * omission - see XrayVpnBuilderPlan's own docs), not tunneled.
         */
        fun xrayRealityAdapterShell(): TransportCapabilities = TransportCapabilities(
            usesUdp = false,
            usesTcp = true,
            supportsPort443 = true,
            supportsObfuscation = true,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /** B35 - executable VLESS/XHTTP CDN-fronted adapter shell. */
        fun xrayXhttpAdapterShell(): TransportCapabilities = TransportCapabilities(
            usesUdp = false,
            usesTcp = true,
            supportsPort443 = true,
            supportsObfuscation = true,
            suitableForRestrictiveNetworks = true,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /**
         * B8O2 - VlessTlsTransport/NovaXrayVpnService (TLS/TCP fallback) as
         * an isolated adapter shell: real code exists (config validation/
         * rendering, the SAME real VpnService/TUN/self-UID-exclusion shell
         * REALITY already uses) but has zero physical-device evidence yet -
         * see [xrayRealityAdapterShell]'s own docs for why this describes
         * only what the adapter code does, never Smart Connect eligibility.
         * Same false capabilities as REALITY's own shell for the same
         * reasons (ALL_APPS only, no IPv6 plumbing).
         */
        fun xrayTlsAdapterShell(): TransportCapabilities = TransportCapabilities(
            usesUdp = false,
            usesTcp = true,
            supportsPort443 = true,
            supportsObfuscation = false,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /**
         * B45B-1 - typed capability facts for the AEAD-2022 shadowsocks-rust
         * protocol/mechanism B45A physically proved on real Android hardware
         * (see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md - FEASIBILITY PROVEN -
         * and docs/B45B_SHADOWSOCKS_PRODUCTION_ADAPTER_DESIGN.md Section 2).
         * As of B45B-1 there is NO `VpnTransport` implementation for this
         * kind yet (no adapter shell class references this factory the way
         * [xrayRealityAdapterShell] etc. are referenced by their own
         * transport classes) - this value exists only so the type is
         * representable; `TransportRegistry` does not register
         * `SHADOWSOCKS_2022` as available.
         *
         * `usesTcp`/`usesUdp`/`supportsFullTunnel` are `true` because B45A
         * physically proved real end-to-end TCP AND UDP data-plane traffic
         * through a real `VpnService` TUN (Section 35 of the spike doc: 3/3
         * exact UDP round-trip matches, repeated TCP proofs). Every other
         * field stays at its safe, truthful default (`false`) because it
         * was never exercised: `supportsRoaming` is `false` because B45A's
         * own Q7 (Wi-Fi/cellular handover) remains explicitly BLOCKED/
         * deferred/UNVERIFIED - this field must never be flipped to `true`
         * without a physical handover proof, regardless of how plausible
         * `RESTART_SESSION` sounds on paper. `suitableForRestrictiveNetworks`
         * is `false` because no censorship-resistance/Russia/hard-whitelist
         * testing was ever performed or claimed. `supportsObfuscation` is
         * `false`: plain AEAD-2022 has no TLS-mimicry/CDN-fronting layer
         * (unlike `XRAY_XHTTP`). `maturity` is `NOT_IMPLEMENTED`, not
         * `EXPERIMENTAL`: unlike the Xray adapter-shell factories above
         * (real adapter code, zero device evidence), this transport has
         * real device evidence (B45A) but zero production adapter code -
         * the opposite gap, and `TransportMaturity` has no value for
         * "protocol proven, no code" - `NOT_IMPLEMENTED` is the only
         * truthful choice until B45B-3's adapter shell exists.
         */
        fun shadowsocks2022(): TransportCapabilities = TransportCapabilities(
            usesUdp = true,
            usesTcp = true,
            supportsPort443 = false,
            supportsObfuscation = false,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.NOT_IMPLEMENTED,
        )

        /**
         * B45B-3 - ShadowsocksTransport/ShadowsocksVpnService as an isolated
         * adapter shell, the same "real code exists, zero/limited physical
         * evidence, not registered AVAILABLE" shape [xrayRealityAdapterShell]
         * documents (TransportRegistry keeps SHADOWSOCKS_2022 at
         * NOT_IMPLEMENTED/[notImplemented] - this factory describes only
         * what the adapter code itself does, never Smart Connect
         * eligibility). usesUdp/usesTcp/supportsFullTunnel stay true -
         * B45A's own physical proof of the underlying mechanism carries over
         * unchanged (see [shadowsocks2022]'s own docs for that evidence).
         * maturity is EXPERIMENTAL, not NOT_IMPLEMENTED: unlike
         * [shadowsocks2022] (protocol proven, zero adapter code), real
         * adapter code now exists here - the same gap
         * [xrayRealityAdapterShell] already describes for Xray.
         */
        fun shadowsocks2022AdapterShell(): TransportCapabilities = TransportCapabilities(
            usesUdp = true,
            usesTcp = true,
            supportsPort443 = false,
            supportsObfuscation = false,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /**
         * B46-4A - Hysteria2Transport/Hysteria2VpnService as an isolated
         * adapter shell: real code exists (process-isolated three-boundary
         * runtime, real VpnService TUN, real protect(fd), typed
         * signed-binding + credential gating) but is deliberately NOT
         * registered AVAILABLE in `TransportRegistry` merely by this
         * factory existing - see `MainViewModel.isHysteria2AvailableFor`'s
         * own docs for the full eligibility gate. `usesUdp`/`usesFullTunnel`
         * are `true` because B46-3C physically proved a real end-to-end
         * QUIC/UDP data plane through a real Android `VpnService` TUN on
         * OPPO CPH2173 (DNS, TCP, direct-IP TCP, UDP, expected exit,
         * server-side correlation - see
         * docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "research
         * evidence inherited" section). Every other field stays at its
         * safe, truthful default:
         *  - `supportsRoaming` is `false` - B46-3C's own physical evidence
         *    covers a stationary session plus two clean reconnect cycles,
         *    never a live network handover; [net.pocvpn.client.vpn.UnderlyingNetworkRecovery.RESTART_SESSION]
         *    is used until seamless roaming is separately, physically
         *    proven.
         *  - `supportsSplitRouting` is `false` - this slice wires FULL_VPN
         *    only (see `Hysteria2Transport`'s own routing-mode doc); a
         *    caller requesting a different `RoutingMode` fails closed
         *    rather than silently downgrading to full tunnel.
         *  - `supportsIpv6`/`supportsTrafficStatistics`/`supportsProbing`
         *    are `false` - none was implemented or evidenced this slice.
         *  - `suitableForRestrictiveNetworks` is deliberately `false`: no
         *    qualifying B54 `FIELD_MEASURED` restricted-network evidence
         *    exists yet for HYSTERIA2 (B54 PR #108 still represents
         *    Hysteria2 as pending/non-production) - this field must never
         *    be set from the protocol's intended purpose or marketing
         *    framing, only from real field evidence.
         *  - `maturity` is `EXPERIMENTAL`: real adapter code exists with
         *    real (lab/architecture) device evidence, but zero production
         *    deployment/normal-selection physical validation yet.
         */
        fun hysteria2AdapterShell(): TransportCapabilities = TransportCapabilities(
            usesUdp = true,
            usesTcp = false,
            supportsPort443 = true,
            supportsObfuscation = true,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = true,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.EXPERIMENTAL,
        )

        /** A transport with no implementation at all: every capability is truthfully false/unknown. */
        fun notImplemented(): TransportCapabilities = TransportCapabilities(
            usesUdp = false,
            usesTcp = false,
            supportsPort443 = false,
            supportsObfuscation = false,
            suitableForRestrictiveNetworks = false,
            supportsRoaming = false,
            supportsFullTunnel = false,
            supportsSplitRouting = false,
            supportsIpv6 = false,
            supportsTrafficStatistics = false,
            supportsProbing = false,
            maturity = TransportMaturity.NOT_IMPLEMENTED,
        )
    }
}
