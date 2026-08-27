package net.pocvpn.client.transport

/**
 * Identifies a VPN/anti-censorship data-plane protocol, independent of
 * whether it is actually implemented yet (see TransportStatus/TransportRegistry).
 * Only AMNEZIA_WG has a real VpnTransport implementation as of Phase 2A -
 * the others are named here so the architecture (registry, orchestrator,
 * Smart Connect decision engine) has somewhere truthful to point at
 * "not implemented yet", never a fake success.
 */
enum class TransportKind {
    AMNEZIA_WG,
    XRAY_REALITY,
    QUIC,
    TLS_TCP,
}
