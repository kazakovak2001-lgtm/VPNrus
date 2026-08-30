package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ManifestVerifierTest {

    private val random = SecureRandom()

    private fun keypair(): Pair<Ed25519PrivateKeyParameters, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(random)
        val pub = priv.generatePublicKey().encoded
        return priv to pub
    }

    private fun sign(priv: Ed25519PrivateKeyParameters, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun manifest(version: Int = 1, issuedAt: Long = 1_000_000L, expiresAt: Long = 2_000_000L, keyId: String = "key-1") = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = issuedAt,
        expiresAtEpochMillis = expiresAt,
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

    private fun sign(manifest: EndpointManifest, priv: Ed25519PrivateKeyParameters): SignedManifest =
        SignedManifest(manifest, sign(priv, ManifestCanonicalizer.canonicalBytes(manifest)))

    @Test
    fun `valid signature verifies`() {
        val (priv, pub) = keypair()
        val m = manifest()
        val signed = sign(m, priv)
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ManifestVerificationResult.Valid, result)
    }

    @Test
    fun `invalid signature (wrong key) is rejected`() {
        val (_, pubA) = keypair()
        val (privB, _) = keypair()
        val m = manifest()
        val signed = sign(m, privB)
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pubA))
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertTrue(result is ManifestVerificationResult.Invalid)
    }

    @Test
    fun `tampered content after signing is rejected`() {
        val (priv, pub) = keypair()
        val signed = sign(manifest(), priv)
        val tampered = signed.copy(manifest = signed.manifest.copy(manifestVersion = 2))
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))
        val result = Ed25519ManifestVerifier().verify(tampered, anchors, nowEpochMillis = 1_500_000L)
        assertTrue(result is ManifestVerificationResult.Invalid)
    }

    @Test
    fun `expired manifest is rejected`() {
        val (priv, pub) = keypair()
        val signed = sign(manifest(issuedAt = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = 3_000_000L)
        assertTrue((result as ManifestVerificationResult.Invalid).reason.contains("expired"))
    }

    @Test
    fun `future issuedAt beyond clock skew tolerance is rejected`() {
        val (priv, pub) = keypair()
        val now = 1_000_000L
        val signed = sign(manifest(issuedAt = now + 10_000_000L, expiresAt = now + 20_000_000L), priv)
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = now)
        assertTrue((result as ManifestVerificationResult.Invalid).reason.contains("future"))
    }

    @Test
    fun `issuedAt within clock skew tolerance is accepted`() {
        val (priv, pub) = keypair()
        val now = 1_000_000L
        val skew = Ed25519ManifestVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS / 2
        val signed = sign(manifest(issuedAt = now + skew, expiresAt = now + 10_000_000L), priv)
        val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = now)
        assertEquals(ManifestVerificationResult.Valid, result)
    }

    @Test
    fun `unknown signing key id is rejected`() {
        val (priv, _) = keypair()
        val signed = sign(manifest(keyId = "unknown-key"), priv)
        val anchors = FixedManifestTrustAnchors(emptyMap())
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertTrue((result as ManifestVerificationResult.Invalid).reason.contains("unknown signing key"))
    }

    /**
     * Cross-language proof: this is the EXACT signature produced offline by
     * gateway/tools/manifest_signing.py for the SAME manifest used in
     * EmbeddedBootstrapManifest - if the Kotlin canonicalizer/verifier ever
     * silently drifts out of byte-for-byte agreement with the Python signer,
     * this test (not just EmbeddedBootstrapManifestTest, which uses the same
     * embedded constants) is the tripwire.
     */
    @Test
    fun `verifies a manifest signed offline by the Python tool`() {
        val signed = EmbeddedBootstrapManifest.signedManifest()
        val anchors = EmbeddedBootstrapManifest.trustAnchors()
        val result = Ed25519ManifestVerifier().verify(signed, anchors, nowEpochMillis = signed.manifest.issuedAtEpochMillis + 1)
        assertEquals(ManifestVerificationResult.Valid, result)
    }
}
