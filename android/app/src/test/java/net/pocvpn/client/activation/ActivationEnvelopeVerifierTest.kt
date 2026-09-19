package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ActivationEnvelopeVerifierTest {

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

    private fun nonce(seed: Byte = 0x01): ByteArray = ByteArray(ActivationEnvelope.NONCE_LENGTH) { (seed + it).toByte() }

    private fun envelope(
        issuedAt: Long = 1_000_000L,
        notBefore: Long = 1_000_000L,
        expiresAt: Long = 2_000_000L,
        keyId: String = "issuer-key-1",
    ) = ActivationEnvelope(
        activationId = ActivationId("a".repeat(32)),
        credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
        issuedAtEpochMillis = issuedAt,
        notBeforeEpochMillis = notBefore,
        expiresAtEpochMillis = expiresAt,
        bootstrapBundleRef = ActivationBundleRef(3, ByteArray(32) { it.toByte() }),
        bootstrapEndpointHints = listOf(EndpointId("gw-a"), EndpointId("gw-b")),
        bootstrapCapabilityHint = ByteArray(8) { it.toByte() },
        nonce = nonce(),
        issuerKeyId = ActivationIssuerKeyId(keyId),
    )

    private fun sign(envelope: ActivationEnvelope, priv: Ed25519PrivateKeyParameters): SignedActivationEnvelope =
        SignedActivationEnvelope(envelope, signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)))

    // ---- happy path ----

    @Test
    fun `valid envelope verifies`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `verify from encoded bytes round trips through the codec`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(), priv)
        val encoded = ActivationEnvelopeCodec.encode(signed)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(encoded, anchors, nowEpochMillis = 1_500_000L)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    // ---- trust anchors ----

    @Test
    fun `unknown issuer key is rejected`() {
        val (priv, _) = keypair()
        val signed = sign(envelope(keyId = "unknown"), priv)
        val anchors = FixedActivationIssuerTrustAnchors(emptyMap())
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.ISSUER_KEY_UNKNOWN, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    @Test
    fun `second simultaneously trusted key verifies`() {
        val (privA, pubA) = keypair()
        val (privB, pubB) = keypair()
        val anchors = FixedActivationIssuerTrustAnchors(
            mapOf(ActivationIssuerKeyId("issuer-key-1") to pubA, ActivationIssuerKeyId("issuer-key-2") to pubB),
        )
        val signedA = sign(envelope(keyId = "issuer-key-1"), privA)
        val signedB = sign(envelope(keyId = "issuer-key-2"), privB)
        assertTrue(Ed25519ActivationEnvelopeVerifier().verify(signedA, anchors, 1_500_000L) is ActivationEnvelopeVerificationResult.Valid)
        assertTrue(Ed25519ActivationEnvelopeVerifier().verify(signedB, anchors, 1_500_000L) is ActivationEnvelopeVerificationResult.Valid)
    }

    // ---- time validation ----

    @Test
    fun `exactly at notBefore is valid`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_000_000L)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `just before tolerated boundary of notBefore is valid`() {
        val (priv, pub) = keypair()
        val skew = Ed25519ActivationEnvelopeVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS
        val signed = sign(envelope(notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_000_000L - skew)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `outside forward-skew tolerance before notBefore is rejected`() {
        val (priv, pub) = keypair()
        val skew = Ed25519ActivationEnvelopeVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS
        val signed = sign(envelope(notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_000_000L - skew - 1)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_NOT_YET_VALID, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    @Test
    fun `exactly at expiresAt is valid`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 2_000_000L)
        assertTrue(result is ActivationEnvelopeVerificationResult.Valid)
    }

    @Test
    fun `just after expiry is rejected with no tolerance`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 2_000_001L)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_EXPIRED, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    @Test
    fun `absurd device clock is reported as CLOCK_UNCERTAIN`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(issuedAt = 1_000_000L, notBefore = 1_000_000L, expiresAt = 2_000_000L), priv)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val absurdNow = 1_000_000L + Ed25519ActivationEnvelopeVerifier.DEFAULT_ABSURD_CLOCK_SKEW_TOLERANCE_MS + 1
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = absurdNow)
        assertEquals(ActivationEnvelopeFailureKind.CLOCK_UNCERTAIN, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    // ---- mutation coverage: every signed field must invalidate the signature ----

    private fun assertMutationInvalidatesSignature(mutate: (ActivationEnvelope) -> ActivationEnvelope) {
        val (priv, pub) = keypair()
        val original = envelope()
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(original))
        val mutated = mutate(original)
        val signed = SignedActivationEnvelope(mutated, signature)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    @Test fun `mutating activationId invalidates signature`() = assertMutationInvalidatesSignature { it.copy(activationId = ActivationId("b".repeat(32))) }
    @Test fun `mutating credential invalidates signature`() = assertMutationInvalidatesSignature { it.copy(credential = ActivationCredential("zzzDEF123_-abcDEF123_-abcDEF123456789")) }
    @Test fun `mutating issuedAt invalidates signature`() = assertMutationInvalidatesSignature { it.copy(issuedAtEpochMillis = it.issuedAtEpochMillis + 1) }
    @Test fun `mutating notBefore invalidates signature`() = assertMutationInvalidatesSignature { it.copy(notBeforeEpochMillis = it.notBeforeEpochMillis + 1) }
    @Test fun `mutating expiresAt invalidates signature`() = assertMutationInvalidatesSignature { it.copy(expiresAtEpochMillis = it.expiresAtEpochMillis + 1) }
    @Test fun `mutating bundle manifestVersion invalidates signature`() = assertMutationInvalidatesSignature {
        it.copy(bootstrapBundleRef = ActivationBundleRef(it.bootstrapBundleRef!!.manifestVersion + 1, it.bootstrapBundleRef!!.contentHash))
    }
    @Test fun `mutating bundle contentHash invalidates signature`() = assertMutationInvalidatesSignature {
        val hash = it.bootstrapBundleRef!!.contentHash.copyOf()
        hash[0] = (hash[0] + 1).toByte()
        it.copy(bootstrapBundleRef = ActivationBundleRef(it.bootstrapBundleRef!!.manifestVersion, hash))
    }
    @Test fun `mutating endpoint hints invalidates signature`() = assertMutationInvalidatesSignature { it.copy(bootstrapEndpointHints = it.bootstrapEndpointHints.reversed()) }
    @Test fun `mutating capability bytes invalidates signature`() = assertMutationInvalidatesSignature {
        val bytes = it.bootstrapCapabilityHint!!.copyOf()
        bytes[0] = (bytes[0] + 1).toByte()
        it.copy(bootstrapCapabilityHint = bytes)
    }
    @Test fun `mutating nonce invalidates signature`() = assertMutationInvalidatesSignature {
        val n = it.nonce.copyOf()
        n[0] = (n[0] + 1).toByte()
        it.copy(nonce = n)
    }
    @Test fun `mutating issuerKeyId invalidates signature (against the ORIGINAL key, since keyId now points elsewhere)`() {
        val (priv, pub) = keypair()
        val original = envelope(keyId = "issuer-key-1")
        val signature = signBytes(priv, ActivationEnvelopeCanonicalizer.canonicalBytes(original))
        val mutated = original.copy(issuerKeyId = ActivationIssuerKeyId("issuer-key-1-but-different"))
        val signed = SignedActivationEnvelope(mutated, signature)
        // Trust BOTH ids to the SAME key so any failure is provably about the
        // signature covering issuerKeyId, not merely an unknown-key lookup miss.
        val anchors = FixedActivationIssuerTrustAnchors(
            mapOf(ActivationIssuerKeyId("issuer-key-1") to pub, ActivationIssuerKeyId("issuer-key-1-but-different") to pub),
        )
        val result = Ed25519ActivationEnvelopeVerifier().verify(signed, anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    @Test
    fun `mutating signature bytes invalidates it`() {
        val (priv, pub) = keypair()
        val signed = sign(envelope(), priv)
        val tamperedSig = signed.signature.copyOf()
        tamperedSig[0] = (tamperedSig[0] + 1).toByte()
        val tampered = SignedActivationEnvelope(signed.envelope, tamperedSig)
        val anchors = FixedActivationIssuerTrustAnchors(mapOf(ActivationIssuerKeyId("issuer-key-1") to pub))
        val result = Ed25519ActivationEnvelopeVerifier().verify(tampered, anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }

    // ---- malformed container ----

    @Test
    fun `malformed encoded package is rejected as PACKAGE_MALFORMED`() {
        val anchors = FixedActivationIssuerTrustAnchors(emptyMap())
        val result = Ed25519ActivationEnvelopeVerifier().verify(byteArrayOf(1, 2, 3), anchors, nowEpochMillis = 1_500_000L)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_MALFORMED, (result as ActivationEnvelopeVerificationResult.Invalid).kind)
    }
}
