package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class ActivationEnvelopeCanonicalizerTest {

    private val random = SecureRandom()

    private fun nonce(seed: Byte = 0x01): ByteArray = ByteArray(ActivationEnvelope.NONCE_LENGTH) { (seed + it).toByte() }

    private fun minimalEnvelope() = ActivationEnvelope(
        activationId = ActivationId("a".repeat(32)),
        credential = ActivationCredential("abcDEF123_-abcDEF123_-abcDEF123456789"),
        issuedAtEpochMillis = 1_000_000L,
        notBeforeEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        bootstrapBundleRef = null,
        bootstrapEndpointHints = emptyList(),
        bootstrapCapabilityHint = null,
        nonce = nonce(),
        issuerKeyId = ActivationIssuerKeyId("issuer-key-1"),
    )

    private fun withBundleRef() = minimalEnvelope().copy(
        bootstrapBundleRef = ActivationBundleRef(3, ByteArray(32) { it.toByte() }),
    )

    private fun withHints() = minimalEnvelope().copy(
        bootstrapEndpointHints = listOf(EndpointId("gw-b"), EndpointId("gw-a"), EndpointId("gw-c")),
    )

    private fun withCapability() = minimalEnvelope().copy(
        bootstrapCapabilityHint = ByteArray(64) { (it * 3).toByte() },
    )

    private fun fullEnvelope() = minimalEnvelope().copy(
        bootstrapBundleRef = ActivationBundleRef(7, ByteArray(32) { (it + 1).toByte() }),
        bootstrapEndpointHints = listOf(EndpointId("gw-z"), EndpointId("gw-a")),
        bootstrapCapabilityHint = ByteArray(16) { it.toByte() },
    )

    private fun roundTrip(envelope: ActivationEnvelope) {
        val bytes1 = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        val bytes2 = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        assertArrayEquals("canonical encoding must be deterministic across repeated calls", bytes1, bytes2)

        val decoded = ActivationEnvelopeCanonicalizer.decode(bytes1)
        assertTrue(decoded is ActivationEnvelopeDecodeResult.Success)
        val decodedEnvelope = (decoded as ActivationEnvelopeDecodeResult.Success).envelope
        assertEquals(envelope, decodedEnvelope)

        val reEncoded = ActivationEnvelopeCanonicalizer.canonicalBytes(decodedEnvelope)
        assertArrayEquals("decode -> encode must reproduce identical bytes", bytes1, reEncoded)
    }

    @Test fun `round trip - minimal envelope`() = roundTrip(minimalEnvelope())
    @Test fun `round trip - with bundle ref`() = roundTrip(withBundleRef())
    @Test fun `round trip - with endpoint hints`() = roundTrip(withHints())
    @Test fun `round trip - with capability hint`() = roundTrip(withCapability())
    @Test fun `round trip - full envelope`() = roundTrip(fullEnvelope())

    @Test
    fun `endpoint hint order is preserved, never sorted`() {
        val envelope = withHints()
        val decoded = (ActivationEnvelopeCanonicalizer.decode(ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)) as ActivationEnvelopeDecodeResult.Success).envelope
        assertEquals(listOf(EndpointId("gw-b"), EndpointId("gw-a"), EndpointId("gw-c")), decoded.bootstrapEndpointHints)
    }

    @Test
    fun `pinned canonical bytes for minimal envelope fixture`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(minimalEnvelope())
        val hex = bytes.joinToString("") { "%02x".format(it) }
        // Pinned tripwire: any accidental wire-format drift (field order,
        // widths, domain tag) changes this hex string. Regenerate
        // deliberately (never silently) if the canonical format changes on
        // purpose - see ActivationEnvelopeCanonicalizer's own docs. Value
        // captured from this exact implementation, not hand-derived.
        assertEquals(PINNED_MINIMAL_ENVELOPE_HEX, hex)
    }

    @Test
    fun `decode rejects wrong domain tag such as a manifest's canonical bytes`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1)
            d.writeInt(1)
        }
        val result = ActivationEnvelopeCanonicalizer.decode(out.toByteArray())
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects unsupported format version`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(minimalEnvelope())
        val mutated = bumpFormatVersion(bytes)
        val result = ActivationEnvelopeCanonicalizer.decode(mutated)
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
        val failure = (result as ActivationEnvelopeDecodeResult.Failure).failure
        assertTrue(failure is ActivationEnvelopeParseFailure.UnsupportedFormatVersion)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_VERSION_UNSUPPORTED, failure.toFailureKind())
    }

    private fun bumpFormatVersion(bytes: ByteArray): ByteArray {
        // domain tag is [len:4][bytes...]; format version Int follows immediately.
        val domainLen = ((bytes[0].toInt() and 0xFF) shl 24) or ((bytes[1].toInt() and 0xFF) shl 16) or
            ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
        val versionOffset = 4 + domainLen
        val copy = bytes.copyOf()
        copy[versionOffset + 3] = (copy[versionOffset + 3] + 1).toByte()
        return copy
    }

    @Test
    fun `decode rejects trailing garbage after a valid payload`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(minimalEnvelope())
        val withTrailing = bytes + byteArrayOf(0x01, 0x02, 0x03)
        val result = ActivationEnvelopeCanonicalizer.decode(withTrailing)
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects empty bytes`() {
        assertTrue(ActivationEnvelopeCanonicalizer.decode(ByteArray(0)) is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects one-byte truncations of a valid payload`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(fullEnvelope())
        for (i in bytes.indices) {
            val truncated = bytes.copyOfRange(0, i)
            val result = ActivationEnvelopeCanonicalizer.decode(truncated)
            assertTrue("truncation at $i must not crash and must be rejected", result is ActivationEnvelopeDecodeResult.Failure)
        }
    }

    @Test
    fun `decode rejects random truncation points deterministically without crashing`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(fullEnvelope())
        val seededRandom = java.util.Random(42)
        repeat(200) {
            val cut = seededRandom.nextInt(bytes.size + 1)
            val truncated = bytes.copyOfRange(0, cut)
            val result = ActivationEnvelopeCanonicalizer.decode(truncated)
            if (cut < bytes.size) {
                assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
            }
        }
    }

    @Test
    fun `decode rejects a corrupted length field (huge declared string length)`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(minimalEnvelope()).copyOf()
        // domain tag length field is the first 4 bytes - corrupt it to something absurd.
        bytes[0] = 0x7f
        bytes[1] = 0x7f
        bytes[2] = 0x7f
        bytes[3] = 0x7f
        val result = ActivationEnvelopeCanonicalizer.decode(bytes)
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects negative declared length`() {
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(minimalEnvelope()).copyOf()
        bytes[0] = 0xFF.toByte()
        bytes[1] = 0xFF.toByte()
        bytes[2] = 0xFF.toByte()
        bytes[3] = 0xFF.toByte()
        val result = ActivationEnvelopeCanonicalizer.decode(bytes)
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects invalid UTF-8 in the domain tag`() {
        // Build a payload with a domain-tag string field containing an invalid UTF-8 byte.
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(3)
            d.write(byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x00))
        }
        val result = ActivationEnvelopeCanonicalizer.decode(out.toByteArray())
        // PR #92 correction: the decoder now uses a STRICT UTF-8 decoder
        // (REPORT on malformed input), so this fails immediately as
        // malformed UTF-8 rather than silently substituting the replacement
        // character and only failing later on domain-tag mismatch.
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
    }

    @Test
    fun `decode rejects invalid UTF-8 in the credential field`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            writeStringField(d, ActivationEnvelopeCanonicalizer.DOMAIN_TAG)
            d.writeInt(ActivationEnvelopeCanonicalizer.FORMAT_VERSION)
            writeStringField(d, "a".repeat(32))
            // credential field: declared length 3, invalid UTF-8 bytes.
            d.writeInt(3)
            d.write(byteArrayOf(0xC0.toByte(), 0xAF.toByte(), 0x00))
        }
        val result = ActivationEnvelopeCanonicalizer.decode(out.toByteArray())
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_MALFORMED, (result as ActivationEnvelopeDecodeResult.Failure).failure.toFailureKind())
    }

    @Test
    fun `decode rejects invalid UTF-8 in an endpoint hint field`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            writeStringField(d, ActivationEnvelopeCanonicalizer.DOMAIN_TAG)
            d.writeInt(ActivationEnvelopeCanonicalizer.FORMAT_VERSION)
            writeStringField(d, "a".repeat(32))
            writeStringField(d, "abcDEF123_-abcDEF123_-abcDEF123456789")
            d.writeLong(1_000_000L)
            d.writeLong(1_000_000L)
            d.writeLong(2_000_000L)
            d.writeBoolean(false) // no bundle ref
            d.writeInt(1) // one endpoint hint
            // malformed UTF-8 hint bytes (overlong encoding, invalid).
            d.writeInt(2)
            d.write(byteArrayOf(0xC0.toByte(), 0xAF.toByte()))
        }
        val result = ActivationEnvelopeCanonicalizer.decode(out.toByteArray())
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_MALFORMED, (result as ActivationEnvelopeDecodeResult.Failure).failure.toFailureKind())
    }

    @Test
    fun `decode rejects invalid UTF-8 in the issuerKeyId field`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            writeStringField(d, ActivationEnvelopeCanonicalizer.DOMAIN_TAG)
            d.writeInt(ActivationEnvelopeCanonicalizer.FORMAT_VERSION)
            writeStringField(d, "a".repeat(32))
            writeStringField(d, "abcDEF123_-abcDEF123_-abcDEF123456789")
            d.writeLong(1_000_000L)
            d.writeLong(1_000_000L)
            d.writeLong(2_000_000L)
            d.writeBoolean(false) // no bundle ref
            d.writeInt(0) // no hints
            d.writeBoolean(false) // no capability hint
            d.writeInt(ActivationEnvelope.NONCE_LENGTH)
            d.write(nonce())
            // malformed UTF-8 issuerKeyId bytes.
            d.writeInt(2)
            d.write(byteArrayOf(0xED.toByte(), 0xA0.toByte()))
        }
        val result = ActivationEnvelopeCanonicalizer.decode(out.toByteArray())
        assertTrue(result is ActivationEnvelopeDecodeResult.Failure)
        assertEquals(ActivationEnvelopeFailureKind.PACKAGE_MALFORMED, (result as ActivationEnvelopeDecodeResult.Failure).failure.toFailureKind())
    }

    private fun writeStringField(d: java.io.DataOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    @Test
    fun `multi-byte UTF-8 endpoint hint round trips when within the byte budget`() {
        // 40 Cyrillic characters, 2 bytes each = 80 UTF-8 bytes, well within the 128-byte cap.
        val hint = EndpointId("ш".repeat(40))
        val envelope = minimalEnvelope().copy(bootstrapEndpointHints = listOf(hint))
        roundTrip(envelope)
    }

    @Test
    fun `endpoint hint exactly at the UTF-8 byte limit round trips`() {
        val hint = EndpointId("a".repeat(ActivationEnvelope.MAX_ENDPOINT_HINT_UTF8_BYTES))
        val envelope = minimalEnvelope().copy(bootstrapEndpointHints = listOf(hint))
        roundTrip(envelope)
    }

    @Test
    fun `endpoint hint one UTF-8 byte over the limit is rejected at construction`() {
        // Each Cyrillic character is 2 UTF-8 bytes; 65 of them = 130 bytes > 128-byte cap,
        // while still satisfying EndpointId's own separate 128-CHARACTER limit (65 chars).
        val hint = EndpointId("ш".repeat(65))
        try {
            minimalEnvelope().copy(bootstrapEndpointHints = listOf(hint))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected: B56-local UTF-8 byte-length boundary, see ActivationEnvelope.init{}
        }
    }

    @Test
    fun `issuerKeyId exactly at the UTF-8 byte limit round trips`() {
        val envelope = minimalEnvelope().copy(issuerKeyId = ActivationIssuerKeyId("k".repeat(ActivationIssuerKeyId.MAX_LENGTH_BYTES)))
        roundTrip(envelope)
    }

    @Test
    fun `issuerKeyId one UTF-8 byte over the limit is rejected at construction`() {
        try {
            ActivationIssuerKeyId("k".repeat(ActivationIssuerKeyId.MAX_LENGTH_BYTES + 1))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `multi-byte UTF-8 issuerKeyId round trips when within the byte budget`() {
        // 30 Cyrillic characters, 2 bytes each = 60 UTF-8 bytes, within the 64-byte cap.
        val envelope = minimalEnvelope().copy(issuerKeyId = ActivationIssuerKeyId("щ".repeat(30)))
        roundTrip(envelope)
    }

    @Test
    fun `maximum-size envelope encodes within limits and round trips`() {
        val maxHints = (0 until ActivationEnvelope.MAX_ENDPOINT_HINTS).map { EndpointId("h".repeat(ActivationEnvelope.MAX_ENDPOINT_HINT_UTF8_BYTES - 4) + "-%03d".format(it)) }
        check(maxHints.all { it.value.toByteArray(Charsets.UTF_8).size == ActivationEnvelope.MAX_ENDPOINT_HINT_UTF8_BYTES }) { "fixture hint length must be exactly at the byte cap" }
        val envelope = fullEnvelope().copy(
            credential = ActivationCredential("c".repeat(ActivationCredential.MAX_LENGTH)),
            issuerKeyId = ActivationIssuerKeyId("k".repeat(ActivationIssuerKeyId.MAX_LENGTH_BYTES)),
            bootstrapEndpointHints = maxHints,
            bootstrapCapabilityHint = ByteArray(ActivationEnvelope.MAX_CAPABILITY_HINT_BYTES) { it.toByte() },
        )
        val bytes = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        assertTrue("max-size canonical envelope must stay within MAX_CANONICAL_BYTES", bytes.size <= ActivationEnvelopeCanonicalizer.MAX_CANONICAL_BYTES)
        roundTrip(envelope)
    }

    @Test
    fun `decode rejects pure random garbage without crashing`() {
        val seededRandom = java.util.Random(7)
        repeat(100) {
            val garbage = ByteArray(seededRandom.nextInt(500))
            seededRandom.nextBytes(garbage)
            val result = ActivationEnvelopeCanonicalizer.decode(garbage)
            assertTrue(result is ActivationEnvelopeDecodeResult.Failure || result is ActivationEnvelopeDecodeResult.Success)
        }
    }

    @Test
    fun `envelope constructor rejects notBefore after expiresAt`() {
        try {
            minimalEnvelope().copy(notBeforeEpochMillis = 5_000_000L, expiresAtEpochMillis = 1_000_000L)
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `envelope constructor rejects wrong nonce length`() {
        try {
            minimalEnvelope().copy(nonce = ByteArray(15))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `envelope constructor rejects too many endpoint hints`() {
        val tooMany = (0..ActivationEnvelope.MAX_ENDPOINT_HINTS).map { EndpointId("gw-$it") }
        try {
            minimalEnvelope().copy(bootstrapEndpointHints = tooMany)
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `envelope constructor rejects duplicate endpoint hints`() {
        try {
            minimalEnvelope().copy(bootstrapEndpointHints = listOf(EndpointId("gw-a"), EndpointId("gw-a")))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `envelope constructor rejects oversized capability hint`() {
        try {
            minimalEnvelope().copy(bootstrapCapabilityHint = ByteArray(ActivationEnvelope.MAX_CAPABILITY_HINT_BYTES + 1))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `activationId rejects malformed values`() {
        val badValues = listOf("", "not-hex", "a".repeat(31), "a".repeat(33), "A".repeat(32))
        badValues.forEach { bad ->
            try {
                ActivationId(bad)
                throw AssertionError("expected rejection for [$bad]")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun `credential rejects empty and malformed values`() {
        try {
            ActivationCredential("")
            throw AssertionError("expected rejection for empty credential")
        } catch (e: IllegalArgumentException) {
            // expected
        }
        try {
            ActivationCredential("has spaces in it")
            throw AssertionError("expected rejection for non-base64url credential")
        } catch (e: IllegalArgumentException) {
            // expected
        }
        try {
            ActivationCredential("a".repeat(ActivationCredential.MAX_LENGTH + 1))
            throw AssertionError("expected rejection for over-length credential")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun `credential toString never exposes the plaintext value`() {
        val credential = ActivationCredential("super-secret-value-abc123")
        assertTrue(!credential.toString().contains("super-secret"))
    }

    @Test
    fun `envelope toString never exposes credential or capability hint bytes`() {
        val envelope = fullEnvelope().copy(credential = ActivationCredential("super-secret-value-abc123"))
        val text = envelope.toString()
        assertTrue(!text.contains("super-secret"))
        assertTrue(text.contains("REDACTED"))
    }

    @Test
    fun `bundleRef rejects wrong content hash length`() {
        try {
            ActivationBundleRef(1, ByteArray(31))
            throw AssertionError("expected rejection")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    companion object {
        // See `pinned canonical bytes for minimal envelope fixture` above.
        private const val PINNED_MINIMAL_ENVELOPE_HEX = "0000001b4e4f56415f41435449564154494f4e5f454e56454c4f50455f563100000001000000206161616161616161616161616161616161616161616161616161616161616161000000256162634445463132335f2d6162634445463132335f2d61626344454631323334353637383900000000000f424000000000000f424000000000001e8480000000000000000000100102030405060708090a0b0c0d0e0f100000000c6973737565722d6b65792d31"
    }
}
