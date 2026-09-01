package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class SignedManifestCodecTest {

    private fun manifest() = EndpointManifest(
        manifestVersion = 3,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 2_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw"), setOf(EndpointRole.GATEWAY), "eu", "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
            ),
        ),
    )

    @Test
    fun `encode then decode round-trips to an equal SignedManifest`() {
        val signed = SignedManifest(manifest(), byteArrayOf(1, 2, 3, 4))
        val decoded = SignedManifestCodec.decode(SignedManifestCodec.encode(signed))
        assertEquals(signed, decoded)
    }

    @Test
    fun `decode rejects an unsupported container format version`() {
        assertThrows(IllegalArgumentException::class.java) {
            SignedManifestCodec.decode(byteArrayOf(0, 0, 0, 99))
        }
    }

    @Test
    fun `decode rejects truncated bytes rather than returning a partial result`() {
        val full = SignedManifestCodec.encode(SignedManifest(manifest(), byteArrayOf(1, 2, 3)))
        assertThrows(Exception::class.java) {
            SignedManifestCodec.decode(full.copyOf(full.size - 5))
        }
    }

    // --- PR #24 audit fix: exact container consumption (no trailing bytes) ---

    @Test
    fun `an exact valid artifact is accepted`() {
        val signed = SignedManifest(manifest(), byteArrayOf(9, 8, 7))
        val bytes = SignedManifestCodec.encode(signed)
        assertEquals(signed, SignedManifestCodec.decode(bytes))
    }

    @Test
    fun `a valid artifact plus ONE trailing byte is rejected`() {
        val bytes = SignedManifestCodec.encode(SignedManifest(manifest(), byteArrayOf(9, 8, 7)))
        val withTrailingByte = bytes + byteArrayOf(0x42)
        val exception = assertThrows(IllegalArgumentException::class.java) {
            SignedManifestCodec.decode(withTrailingByte)
        }
        assertTrue(exception.message!!.contains("trailing"))
    }

    @Test
    fun `a valid artifact plus many trailing bytes is rejected`() {
        val bytes = SignedManifestCodec.encode(SignedManifest(manifest(), byteArrayOf(9, 8, 7)))
        val withTrailingJunk = bytes + ByteArray(4096) { 0x7A }
        assertThrows(IllegalArgumentException::class.java) {
            SignedManifestCodec.decode(withTrailingJunk)
        }
    }

    @Test
    fun `a truncated signature (declared length longer than what follows) is rejected`() {
        val bytes = SignedManifestCodec.encode(SignedManifest(manifest(), byteArrayOf(1, 2, 3, 4, 5)))
        // Drop the last 2 bytes of the 5-byte signature - sigLen still says
        // 5, but only 3 signature bytes actually remain.
        val truncatedSignature = bytes.copyOf(bytes.size - 2)
        assertThrows(Exception::class.java) {
            SignedManifestCodec.decode(truncatedSignature)
        }
    }

    @Test
    fun `an implausibly large declared canonical length is still rejected (malformed lengths)`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1) // FORMAT_VERSION
            d.writeInt(50_000_000) // way beyond MAX_CANONICAL_BYTES
            d.write(ByteArray(10))
        }
        assertThrows(Exception::class.java) {
            SignedManifestCodec.decode(out.toByteArray())
        }
    }

    @Test
    fun `an implausibly large declared signature length is still rejected (malformed lengths)`() {
        val canonical = ManifestCanonicalizer.canonicalBytes(manifest())
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1) // FORMAT_VERSION
            d.writeInt(canonical.size)
            d.write(canonical)
            d.writeInt(9_999) // way beyond MAX_SIGNATURE_BYTES (256)
            d.write(ByteArray(10))
        }
        assertThrows(Exception::class.java) {
            SignedManifestCodec.decode(out.toByteArray())
        }
    }

    @Test
    fun `a negative declared length is rejected, not treated as zero or wrapped`() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1)
            d.writeInt(-1)
        }
        assertThrows(Exception::class.java) {
            SignedManifestCodec.decode(out.toByteArray())
        }
    }

    /**
     * B12 cross-language proof: this is the EXACT artifact bytes produced
     * by `python3 gateway/tools/manifest_signing.py sign-and-package` for
     * the SAME manifest/key EmbeddedBootstrapManifest already embeds - if
     * pack_signed_manifest (Python) ever drifts from SignedManifestCodec
     * (Kotlin), this decode either throws or produces a different
     * SignedManifest than the one EmbeddedBootstrapManifest.signedManifest()
     * already proves verifies (see EmbeddedBootstrapManifestTest).
     */
    @Test
    fun `decodes the artifact produced by gateway tools manifest_signing py sign-and-package`() {
        val artifactBase64 =
            "AAAAAQAAAXkAAAABAAAAAQAAAaBZ/25YAAABo/j4HlgAAAAccHJvZC1tYW5pZmVzdC1rZXktMjAyNi0wOS0wMQAAAAIAAAAJZnJhbmtmdXJ0AAAAAgAAAAEAAAACAAAAE0dlcm1hbnkgLyBGcmFua2Z1cnQAAAAMT3JhY2xlIENsb3VkAAAAAAAAAAADAAAAAAAAAAsxNTIuNzAuNDMuMQAAymwAAAAAAAAAAQAAAAsxNTIuNzAuNDMuMQAACAUAAAAAAAAAAwAAAAsxNTIuNzAuNDMuMQAACCMAAAAAAAAAAAAAAAAJc3RvY2tob2xtAAAAAgAAAAEAAAACAAAAElN3ZWRlbiAvIFN0b2NraG9sbQAAAANBV1MAAAAAAAAAAAMAAAAAAAAADjE2LjE3MC4yMDguMjMxAADKbAAAAAAAAAABAAAADjE2LjE3MC4yMDguMjMxAAAIBQAAAAAAAAADAAAADjE2LjE3MC4yMDguMjMxAAAIIwAAAAAAAAAAAAAAAEB1LEWjX/97s3b3RNZRmDok5r4w6jkjZpnFAQExZgbExWxCyGWJ5seuiDaZzgcZE7N+/h7sSjps7yiYD3neNUIL"
        val bytes = Base64.getDecoder().decode(artifactBase64)
        val decoded = SignedManifestCodec.decode(bytes)

        // Must be the SAME manifest/signature EmbeddedBootstrapManifest embeds.
        val embedded = EmbeddedBootstrapManifest.signedManifest()
        assertEquals(embedded.manifest, decoded.manifest)
        assertArrayEquals(embedded.signature, decoded.signature)

        val result = Ed25519ManifestVerifier().verify(decoded, EmbeddedBootstrapManifest.trustAnchors(), decoded.manifest.issuedAtEpochMillis + 1)
        assertEquals(ManifestVerificationResult.Valid, result)
    }
}
