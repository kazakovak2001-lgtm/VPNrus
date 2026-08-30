package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
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
            "AAAAAQAAAMkAAAABAAAAAQAAAaBS+UvzAAABrwJbo/MAAAAPYm9vdHN0cmFwLWtleS0xAAAAAQAAAAlmcmFua2Z1cnQAAAACAAAAAQAAAAIAAAATR2VybWFueSAvIEZyYW5rZnVydAAAAAdoZXR6bmVyAAAAAAAAAAADAAAAAAAAAAsxNTIuNzAuNDMuMQAAymwAAAAAAAAAAQAAAAsxNTIuNzAuNDMuMQAACAUAAAAAAAAAAwAAAAsxNTIuNzAuNDMuMQAACCMAAAAAAAAAAAAAAABAl3kGonyTGrPasKZA/jEB/vt7fwy87M0qThk3Nv8ekSSqU227ILiasYnOFI5ClN4FX6uoLcdLqrBiQcHQU4NBAQ=="
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
