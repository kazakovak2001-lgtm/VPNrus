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
 * No production activation-issuer key is populated here or anywhere in
 * this slice - see [FixedActivationIssuerTrustAnchors]'s docs. Ceremony/
 * population of real trust anchors is B56-4's responsibility.
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
 * convention. Production key material is never committed here; this slice
 * only ever constructs instances from test-only key material under test
 * sources.
 */
class FixedActivationIssuerTrustAnchors(private val keys: Map<ActivationIssuerKeyId, ByteArray>) : ActivationIssuerTrustAnchors {
    override fun publicKeyFor(keyId: ActivationIssuerKeyId): ByteArray? = keys[keyId]
}
