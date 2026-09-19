package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
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

    // ---- PR #92 second pass, issue 2: canonical Base64URL, not merely alphabet-valid ----

    @Test
    fun `java Base64 decoder accepts two different strings for the same bytes - demonstrates why alphabet checking alone is not enough`() {
        val decoder = java.util.Base64.getUrlDecoder()
        // Both "AA" and "AB" are valid URL-safe-alphabet, unpadded strings,
        // and BOTH decode to the same single byte - only the trailing 4 bits
        // differ, and those bits are unused/ignored by a length-1 output.
        assertArrayEquals(byteArrayOf(0), decoder.decode("AA"))
        assertArrayEquals(byteArrayOf(0), decoder.decode("AB"))
    }

    @Test
    fun `encode() output round trips through decode()`() {
        val signed = signedEnvelope()
        val canonicalText = ActivationEnvelopeTextCodec.encode(signed)
        val result = ActivationEnvelopeTextCodec.decode(canonicalText)
        assertTrue(result is SignedActivationEnvelopeDecodeResult.Success)
    }

    @Test
    fun `non-canonical pad-bit alias is rejected while its canonical equivalent is not`() {
        // "AA" is the canonical Base64URL-no-padding encoding of the single
        // byte 0 (its trailing unused bits are all zero); "AB" decodes to the
        // SAME byte but is NOT the canonical string for it (proven above).
        // ActivationEnvelopeTextCodec must reject "AB" - it fails the
        // re-encode-and-compare check even though DECODER.decode("AB")
        // itself succeeds.
        val abResult = ActivationEnvelopeTextCodec.decode("AB")
        assertTrue(abResult is SignedActivationEnvelopeDecodeResult.Failure)
        assertEquals(ActivationEnvelopeParseFailure.TruncatedOrMalformed, (abResult as SignedActivationEnvelopeDecodeResult.Failure).failure)

        // "AA" passes the canonical check (it re-encodes to itself) and is
        // handed to ActivationEnvelopeCodec.decode, which then correctly
        // rejects it for an unrelated reason (too short to be a real
        // container) - proving the canonical check does not itself block a
        // string it should accept.
        val aaResult = ActivationEnvelopeTextCodec.decode("AA")
        assertTrue(aaResult is SignedActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode is canonical end to end - only the exact encode() output is accepted for a crafted short payload`() {
        // Build a minimal well-formed encoded package deliberately short
        // enough that its final base64 group has unused bits, so a
        // non-canonical alias actually exists for it.
        val priv = Ed25519PrivateKeyParameters(random)
        val envelope = ActivationEnvelope(
            activationId = ActivationId("a".repeat(32)),
            credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
            issuedAtEpochMillis = 1_000_000L,
            notBeforeEpochMillis = 1_000_000L,
            expiresAtEpochMillis = 2_000_000L,
            bootstrapBundleRef = null,
            bootstrapEndpointHints = emptyList(),
            bootstrapCapabilityHint = null,
            nonce = ByteArray(ActivationEnvelope.NONCE_LENGTH) { it.toByte() },
            issuerKeyId = ActivationIssuerKeyId("issuer-key-1"),
        )
        val canonical = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(canonical, 0, canonical.size)
        val signed = SignedActivationEnvelope(envelope, signer.generateSignature())
        val encodedBytes = ActivationEnvelopeCodec.encode(signed)

        val canonicalText = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(encodedBytes)

        // Flip the last character to a different alphabet character that the
        // JVM decoder still accepts as an equivalent, non-canonical encoding
        // of the SAME trailing byte (find one deterministically).
        val decoder = java.util.Base64.getUrlDecoder()
        val originalBytes = decoder.decode(canonicalText)
        val lastChar = canonicalText.last()
        val alias = ('A'..'Z') + ('a'..'z') + ('0'..'9') + listOf('-', '_')
        val nonCanonicalLastChar = alias.first { candidate ->
            candidate != lastChar &&
                runCatching { decoder.decode(canonicalText.dropLast(1) + candidate) }.getOrNull()?.contentEquals(originalBytes) == true
        }
        val nonCanonicalText = canonicalText.dropLast(1) + nonCanonicalLastChar

        assertTrue(
            "expected a non-canonical alias to exist and decode to the same bytes as a test precondition",
            decoder.decode(nonCanonicalText).contentEquals(originalBytes),
        )

        assertTrue(ActivationEnvelopeTextCodec.decode(canonicalText) is SignedActivationEnvelopeDecodeResult.Success)
        assertTrue(
            "non-canonical alias must be rejected even though it decodes to identical bytes",
            ActivationEnvelopeTextCodec.decode(nonCanonicalText) is SignedActivationEnvelopeDecodeResult.Failure,
        )
    }
}
