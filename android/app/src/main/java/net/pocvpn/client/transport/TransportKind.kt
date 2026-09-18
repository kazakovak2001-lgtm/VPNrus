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
    /** VLESS over Xray XHTTP; deliberately distinct from generic TLS_TCP. */
    XRAY_XHTTP,
    /**
     * B45B-1 - an independent shadowsocks-rust runtime speaking AEAD-2022
     * (`2022-blake3-aes-256-gcm`) specifically, never routed through Xray's
     * own module (see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md - FEASIBILITY
     * PROVEN - and docs/B45B_SHADOWSOCKS_PRODUCTION_ADAPTER_DESIGN.md
     * Section 1's own naming rationale). Deliberately not a generic
     * SHADOWSOCKS value: AEAD-2022's raw-key/per-session-subkey model is
     * materially different from legacy AEAD Shadowsocks, matching this
     * enum's own existing pattern of one value per materially distinct wire
     * protocol (XRAY_REALITY vs XRAY_XHTTP vs TLS_TCP). TYPES ONLY as of
     * B45B-1 - no runtime, no VpnTransport implementation, not registered
     * with TransportOrchestrator/Smart Connect (see TransportRegistry's own
     * NOT_IMPLEMENTED convention).
     */
    SHADOWSOCKS_2022,
}
