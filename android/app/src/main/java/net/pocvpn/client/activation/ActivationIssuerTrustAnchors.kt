package net.pocvpn.client.activation

/**
 * The client's embedded trust roots for the ACTIVATION authority only.
 * Mirrors [net.pocvpn.client.reachability.ManifestTrustAnchors]'s shape,
 * but is a completely separate type over [ActivationIssuerKeyId] (not
 * [net.pocvpn.client.reachability.TrustedKeyId]) - the type system alone
 * makes it impossible to hand a manifest trust-anchor set to an
 * [ActivationEnvelopeVerifier] or vice versa. See
 * ActivationIssuerTrustAnchorsTest for an explicit proof of this
 * separation.
 *
 * A production activation-issuer PUBLIC key is committed through
 * [ProductionActivationIssuerTrustAnchors] (B56-4B1) - see that object's
 * docs and `docs/B56_ACTIVATION_ISSUER_KEY_CEREMONY.md`'s "Production
 * ceremony" section.
 *
 * The corresponding PRIVATE key exists only outside this repository, in
 * the operator-controlled ceremony location.
 *
 * Runtime bootstrap consumption/wiring of the production trust anchor
 * remains B56-5's responsibility - nothing in this slice calls
 * [ProductionActivationIssuerTrustAnchors.trustAnchors] from any
 * networking, UI, or reachability code.
 */
interface ActivationIssuerTrustAnchors {
    fun publicKeyFor(keyId: ActivationIssuerKeyId): ByteArray?
}

/**
 * B56-1 - a fixed, in-memory set of activation-issuer public keys. Deliberately
 * NOT the same class/instance as
 * [net.pocvpn.client.reachability.FixedManifestTrustAnchors] even though
 * the shape is identical - keeping them distinct types is what makes the
 * activation/manifest trust separation a compile-time property, not just a
 * convention. This class never contains key material itself - it is
 * populated with test-only key material under test sources, and, since
 * B56-4B1, with the real production activation-issuer PUBLIC key by
 * [ProductionActivationIssuerTrustAnchors] under main sources. It never
 * holds private key material in either case.
 *
 * [keys] is defensively copied - both the map structure itself and each
 * public-key `ByteArray` value - at construction time, and [publicKeyFor]
 * hands back a fresh copy on every call (PR #92 correction). Without this,
 * a caller who mutated the `Map`/`ByteArray` they originally passed in, or
 * who mutated an array this class had handed back, could change which key
 * bytes an already-constructed trust-anchor set actually verifies against.
 */
class FixedActivationIssuerTrustAnchors(keys: Map<ActivationIssuerKeyId, ByteArray>) : ActivationIssuerTrustAnchors {
    private val keys: Map<ActivationIssuerKeyId, ByteArray> = keys.mapValues { (_, publicKey) -> publicKey.copyOf() }

    override fun publicKeyFor(keyId: ActivationIssuerKeyId): ByteArray? = keys[keyId]?.copyOf()
}
