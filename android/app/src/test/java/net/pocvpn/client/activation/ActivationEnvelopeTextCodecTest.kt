package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/** PR #92 blocker 4 - dedicated coverage for [ActivationEnvelopeTextCodec]'s pre-decode size bound and canonical strictness. */
class ActivationEnvelopeTextCodecTest {

    private val random = SecureRandom()

    private fun signedEnvelope(): SignedActivationEnvelope {
        val priv = Ed25519PrivateKeyParameters(random)
        val envelope = ActivationEnvelope(
            activationId = ActivationId("a".repeat(32)),
            credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
            issuedAtEpochMillis = 1_000_000L,
            notBeforeEpochMillis = 1_000_000L,
            expiresAtEpochMillis = 2_000_000L,
            bootstrapBundleRef = null,
            bootstrapEndpointHints = listOf(EndpointId("gw-a")),
            bootstrapCapabilityHint = null,
            nonce = ByteArray(ActivationEnvelope.NONCE_LENGTH) { it.toByte() },
            issuerKeyId = ActivationIssuerKeyId("issuer-key-1"),
        )
        val canonical = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(canonical, 0, canonical.size)
        return SignedActivationEnvelope(envelope, signer.generateSignature())
    }

    @Test
    fun `valid round trip`() {
        val signed = signedEnvelope()
        val text = ActivationEnvelopeTextCodec.encode(signed)
        val result = ActivationEnvelopeTextCodec.decode(text)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Success)
        assertEquals(signed.envelope, (result as SignedActivationEnvelopeDecodeResult.Success).signed.envelope)
    }

    @Test
    fun `encoder never emits padding`() {
        val text = ActivationEnvelopeTextCodec.encode(signedEnvelope())
        assertFalse(text.contains("="))
    }

    @Test
    fun `decoder rejects a padded form even though it would otherwise decode`() {
        val text = ActivationEnvelopeTextCodec.encode(signedEnvelope())
        val padded = text + "=="
        val result = ActivationEnvelopeTextCodec.decode(padded)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decoder rejects whitespace`() {
        val text = ActivationEnvelopeTextCodec.encode(signedEnvelope())
        val withWhitespace = text.substring(0, text.length / 2) + " " + text.substring(text.length / 2)
        val result = ActivationEnvelopeTextCodec.decode(withWhitespace)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decoder rejects the standard (non-URL-safe) base64 alphabet`() {
        // '+' and '/' are never part of a URL-safe base64url encoding.
        val result = ActivationEnvelopeTextCodec.decode("a+b/c")
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decoder rejects empty text`() {
        val result = ActivationEnvelopeTextCodec.decode("")
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decoder rejects oversized text before any decode allocation`() {
        // A string of valid-alphabet characters, longer than MAX_TEXT_LENGTH could ever legitimately be.
        val oversized = "a".repeat(ActivationEnvelopeTextCodec.MAX_TEXT_LENGTH + 4)
        val result = ActivationEnvelopeTextCodec.decode(oversized)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
        assertEquals(
            ActivationEnvelopeParseFailure.EncodedPackageTooLarge,
            (result as SignedActivationEnvelopeDecodeResult.Failure).failure,
        )
    }

    @Test
    fun `truncated or corrupt encoded text maps to a typed malformed result, never a crash`() {
        val text = ActivationEnvelopeTextCodec.encode(signedEnvelope())
        val truncated = text.substring(0, text.length / 2)
        val result = ActivationEnvelopeTextCodec.decode(truncated)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `MAX_TEXT_LENGTH is derived from the binary codec's own limit, not a duplicated constant`() {
        val expected = ((ActivationEnvelopeCodec.MAX_ENCODED_BYTES + 2) / 3) * 4
        assertEquals(expected, ActivationEnvelopeTextCodec.MAX_TEXT_LENGTH)
    }
}
