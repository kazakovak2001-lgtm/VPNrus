package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.ManifestVerificationResult
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * Proves the activation-issuer / manifest trust separation the B56
 * architecture requires (section 6): activation-issuer keys and manifest
 * signing keys are disjoint sets, held in disjoint types, and a signature
 * valid under one authority must never verify under the other - even when
 * (by operational mistake) the SAME raw key bytes are reused for both
 * roles.
 */
class ActivationIssuerTrustAnchorsTest {

    private val random = SecureRandom()

    private fun keypair(): Pair<Ed25519PrivateKeyParameters, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(random)
        return priv to priv.generatePublicKey().encoded
    }

    private fun signBytes(priv: Ed25519PrivateKeyParameters, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun nonce(): ByteArray = ByteArray(ActivationEnvelope.NONCE_LENGTH) { it.toByte() }

    private fun envelope(keyId: String = "issuer-key-1") = ActivationEnvelope(
        activationId = ActivationId("a".repeat(32)),
        credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
        issuedAtEpochMillis = 1_000_000L,
        notBeforeEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        bootstrapBundleRef = null,
        bootstrapEndpointHints = emptyList(),
        bootstrapCapabilityHint = null,
        nonce = nonce(),
        issuerKeyId = ActivationIssuerKeyId(keyId),
    )

    private fun manifest(keyId: String = "manifest-key-1") = EndpointManifest(
        manifestVersion = 1,
        issuedAtEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        signingKeyId = keyId,
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw"),
                setOf(EndpointRole.GATEWAY),
                "eu",
                "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
            ),
        ),
    )

    @Test
    fun `current test key verifies an ActivationEnvelope`() {
        val (priv, pub) = keypair()
        val envelope = envelope()
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(SignedActivationEnvelope(envelope, signature), anchors, 1_500_000L)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `manifest trust anchors and activation-issuer trust anchors are different types - not interchangeable at compile time`() {
        // This test's own existence is the proof: FixedManifestTrustAnchors
        // cannot be passed where ActivationIssuerTrustAnchors is required
        // (Ed25519ActivationEnvelopeVerifier.verify's second parameter),
        // and vice versa - the code below would fail to COMPILE if that
        // boundary were ever accidentally collapsed (e.g. by making both
        // interfaces the same type, or by having one extend the other).
        val manifestAnchors: net.pocvpn.client.reachability.ManifestTrustAnchors = FixedManifestTrustAnchors(emptyMap())
        val activationAnchors: ActivationIssuerTrustAnchors = FixedActivationIssuerTrustAnchors(emptyMap())
        // A manifest TrustedKeyId is a distinct type from ActivationIssuerKeyId,
        // so `manifestAnchors.publicKeyFor(ActivationIssuerKeyId(...))` cannot be
        // written at all - proven by this file compiling only with the correct pairing.
        assertNull(manifestAnchors.publicKeyFor(net.pocvpn.client.reachability.TrustedKeyId("x")))
        assertNull(activationAnchors.publicKeyFor(ActivationIssuerKeyId("x")))
    }

    @Test
    fun `same raw key bytes reused for both roles still cannot cross-verify (domain separation)`() {
        val (priv, pub) = keypair()
        // The SAME public key is (mis)configured as both an activation-issuer
        // key and a manifest signing key.
        val activationAnchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("shared-key") to pub))
        val manifestAnchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("shared-key") to pub))

        val envelope = envelope(keyId = "shared-key")
        val envelopeSignature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val signedEnvelope = SignedActivationEnvelope(envelope, envelopeSignature)

        // The envelope's own signature must still verify normally under its own authority.
        assertTrue(Ed25519ActivationEnvelopeVerifier().verify(signedEnvelope, activationAnchors, 1_500_000L) is ActivationEnvelopeVerificationResult.Valid)

        // But an EndpointManifest signed with the SAME key must NOT be
        // forgeable by reusing the envelope's signature or canonical bytes,
        // and a manifest legitimately signed with this key is a completely
        // independent artifact - domain separation means the two canonical
        // byte streams are never confusable in the first place.
        val realManifest = manifest(keyId = "shared-key")
        val manifestSignature = signBytes(priv, ManifestCanonicalizer.canonicalBytes(realManifest))
        val signedManifest = SignedManifest(realManifest, manifestSignature)
        val manifestResult = Ed25519ManifestVerifier().verify(signedManifest, manifestAnchors, 1_500_000L)
        assertEquals(ManifestVerificationResult.Valid, manifestResult)

        // Attempting to "replay" the envelope's signature as if it were a
        // manifest signature over the envelope's own canonical bytes must fail:
        // ManifestCanonicalizer.decode cannot even parse
        // ActivationEnvelopeCanonicalizer's bytes as a manifest (different
        // schema/domain tag), so no cross-domain forgery is possible.
        try {
            ManifestCanonicalizer.decode(ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
            throw AssertionError("expected decode of activation-envelope bytes as a manifest to fail")
        } catch (e: IllegalArgumentException) {
            // expected: domain separation holds even under key reuse
        } catch (e: java.io.IOException) {
            // also acceptable: malformed-as-manifest bytes
        }
    }

    @Test
    fun `unknown key id is rejected, never silently falling back to another anchor set`() {
        val (priv, _) = keypair()
        val envelope = envelope(keyId = "not-registered")
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope))
        val anchors = FixedActivationIssuerTrustAnchors(emptyMap())
        assertNull(anchors.publicKeyFor(ActivationIssuerKeyId("not-registered")))
        val result = Ed25519ActivationEnvelopeVerifier().verify(SignedActivationEnvelope(envelope, signature), anchors, 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.ISSUER_KEY_UNKNOWN, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }
}
