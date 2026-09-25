package net.pocvpn.client.transport

/**
 * Identifies a VPN/anti-censorship data-plane protocol, independent of
 * whether it is actually implemented yet (see TransportStatus/TransportRegistry).
 * Only AMNEZIA_WG has a real VpnTransport implementation as of Phase 2A -
 * the others are named here so the architecture (registry, orchestrator,
 * Smart Connect decision engine) has somewhere truthful to point at
 * "not implemented yet", never a fake success.
 */
enum class TransportKind(
    /**
     * B-WL-R6 - the STABLE wire/persistence identifier, written wherever a
     * kind leaves the process: signed endpoint manifests (EndpointManifest
     * codec + gateway/tools/manifest_signing.py `kindOrdinal`), and the local
     * PathHistoryStore / ConnectionOutcomeStore files. It is a mandatory
     * constructor argument, so a new kind cannot compile without choosing one.
     *
     * Values 0-5 are frozen to the enum ordinals the wire format has always
     * carried (existing signed manifests v1-v4 and the embedded bootstrap stay
     * byte-for-byte and signature-for-signature identical - see
     * ManifestWireCompatibilityTest). NEVER change or reuse an existing value;
     * NEVER use [ordinal] for anything that is persisted or signed. The enum's
     * declaration order is no longer a protocol contract.
     *
     * A stable id does NOT make an older client tolerant of an id it does not
     * know - it still rejects the whole manifest (see
     * docs/B_WL_R6_MANIFEST_TRANSPORT_KIND_ROLLOUT.md).
     */
    val wireId: Int,
) {
    AMNEZIA_WG(0),
    XRAY_REALITY(1),
    QUIC(2),
    TLS_TCP(3),
    /** VLESS over Xray XHTTP; deliberately distinct from generic TLS_TCP. */
    XRAY_XHTTP(4),
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
    SHADOWSOCKS_2022(5),
    /**
     * B-WL-R6 - VLESS over Xray XHTTP secured by REALITY (TCP/443 class),
     * distinct from [XRAY_XHTTP] (TLS, CDN-fronted relay ingress) and
     * [XRAY_REALITY] (REALITY over RAW TCP): a different wire protocol, so a
     * different value, per this enum's own convention. Wire id 6 is reserved
     * for it. Rollout caveat: a client older than this value rejects any
     * manifest containing a binding with wire id 6, so such a binding must
     * never be published in the schema-1 manifest older clients fetch.
     */
    XRAY_REALITY_XHTTP(6),
    ;

    companion object {
        private val byWireId: Map<Int, TransportKind> = entries.associateBy { it.wireId }

        /** The kind for a stable wire id, or null when this build does not know it (callers fail closed). */
        fun fromWireId(wireId: Int): TransportKind? = byWireId[wireId]
    }
}
