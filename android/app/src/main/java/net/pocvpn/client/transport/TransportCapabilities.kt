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
