package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.Base64

/**
 * B-WL-R6 - byte-for-byte and signature-for-signature compatibility of the
 * signed manifest wire format against the REAL signed production artifacts
 * (gateway/tools/endpoint-manifest-*.bin, v1-v4; v4 is the deployed file) and
 * the embedded bootstrap manifest. These files are golden: their SHA-256 is
 * pinned below so a fixture can never be "fixed" to make this test pass.
 */
class ManifestWireCompatibilityTest {

    private data class Fixture(val file: String, val sha256: String, val version: Int, val wireKinds: Set<TransportKind>)

    private val fixtures = listOf(
        Fixture("endpoint-manifest-2026-09-01.bin", "39b0550006ead1945d78917e376c49f1382a1ec7f4d4b0e196bd4b66cc3b7c94", 1,
            setOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.TLS_TCP)),
        Fixture("endpoint-manifest-2026-09-01_v2.bin", "2643ff6bfb8df38517e221f79ac02aa471a0cc51ff95610b151a5aca24a2c40a", 2,
            setOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.TLS_TCP)),
        Fixture("endpoint-manifest-2026-09-14-v3.bin", "9c4ebbd19b90759256cb8890d7412bb7ca01e531ac12e609d23b967be3992ebb", 3,
            setOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.TLS_TCP, TransportKind.XRAY_XHTTP)),
        Fixture("endpoint-manifest-2026-09-20-v4.bin", "304722f23ed2c97f94cb0af5122c3bfd4c5d47e3188bb1e991fcd25b1be8a9ad", 4,
            setOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.TLS_TCP, TransportKind.XRAY_XHTTP, TransportKind.SHADOWSOCKS_2022)),
    )

    /** Unit tests run with the :app module as working directory; the fixtures live in the repository's gateway/tools. */
    private fun bytesOf(name: String): ByteArray {
        val file = File("../../gateway/tools/$name")
        assertTrue("golden fixture missing: ${file.absolutePath}", file.isFile)
        return file.readBytes()
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /** The canonical-bytes slice of the container, exactly as received: [format][len][canonical]... */
    private fun canonicalSlice(container: ByteArray): ByteArray {
        val len = java.nio.ByteBuffer.wrap(container, 4, 4).int
        return container.copyOfRange(8, 8 + len)
    }

    @Test
    fun `golden fixtures are the pinned, unmodified production artifacts`() {
        fixtures.forEach { assertEquals(it.file, it.sha256, sha256(bytesOf(it.file))) }
    }

    @Test
    fun `decode then re-encode reproduces every v1-v4 container byte-for-byte`() {
        fixtures.forEach { f ->
            val original = bytesOf(f.file)
            val decoded = SignedManifestCodec.decode(original)
            assertArrayEquals(f.file, original, SignedManifestCodec.encode(decoded))
            assertArrayEquals("${f.file} canonical", canonicalSlice(original), ManifestCanonicalizer.canonicalBytes(decoded.manifest))
            assertEquals(f.version, decoded.manifest.manifestVersion)
            assertEquals(f.file, f.wireKinds, decoded.manifest.endpoints.flatMap { e -> e.transports.map { it.kind } }.toSet())
        }
    }

    @Test
    fun `every v1-v4 production signature still verifies against the embedded trust anchors`() {
        fixtures.forEach { f ->
            val decoded = SignedManifestCodec.decode(bytesOf(f.file))
            val result = Ed25519ManifestVerifier().verify(decoded, EmbeddedBootstrapManifest.trustAnchors(), decoded.manifest.issuedAtEpochMillis + 1)
            assertEquals(f.file, ManifestVerificationResult.Valid, result)
        }
    }

    @Test
    fun `decoding the same bytes twice yields equal manifests (decode is deterministic)`() {
        fixtures.forEach { f ->
            assertEquals(f.file, SignedManifestCodec.decode(bytesOf(f.file)), SignedManifestCodec.decode(bytesOf(f.file)))
        }
    }

    @Test
    fun `embedded bootstrap manifest re-encodes to its exact canonical bytes and its signature verifies`() {
        val signed = EmbeddedBootstrapManifest.signedManifest()
        val canonicalField = EmbeddedBootstrapManifest::class.java.getDeclaredField("CANONICAL_BYTES_BASE64").apply { isAccessible = true }
        val canonical = Base64.getDecoder().decode(canonicalField.get(null) as String)
        assertArrayEquals(canonical, ManifestCanonicalizer.canonicalBytes(signed.manifest))
        assertEquals(
            ManifestVerificationResult.Valid,
            Ed25519ManifestVerifier().verify(signed, EmbeddedBootstrapManifest.trustAnchors(), signed.manifest.issuedAtEpochMillis + 1),
        )
        assertTrue("bootstrap must not carry XRAY_REALITY_XHTTP", signed.manifest.endpoints.none { e -> e.transports.any { it.kind == TransportKind.XRAY_REALITY_XHTTP } })
    }

    @Test
    fun `no production fixture carries XRAY_REALITY_XHTTP (wire id 6)`() {
        fixtures.forEach { f ->
            val kinds = SignedManifestCodec.decode(bytesOf(f.file)).manifest.endpoints.flatMap { e -> e.transports.map { it.kind } }
            assertTrue(f.file, TransportKind.XRAY_REALITY_XHTTP !in kinds)
        }
    }

    private fun manifestWith(kind: TransportKind) = EndpointManifest(
        manifestVersion = 9, issuedAtEpochMillis = 1_000, expiresAtEpochMillis = 2_000,
        endpoints = listOf(
            EndpointDescriptor(EndpointId("gw"), setOf(EndpointRole.GATEWAY), "eu", "p", transports = listOf(EndpointTransportBinding(kind, "203.0.113.1", 443))),
        ),
        signingKeyId = "k",
    )

    @Test
    fun `XRAY_REALITY_XHTTP is written as wire id 6 and decodes back on a client that knows it`() {
        val bytes = ManifestCanonicalizer.canonicalBytes(manifestWith(TransportKind.XRAY_REALITY_XHTTP))
        val decoded = ManifestCanonicalizer.decode(bytes)
        assertEquals(TransportKind.XRAY_REALITY_XHTTP, decoded.endpoints.single().transports.single().kind)
        assertEquals(6, java.nio.ByteBuffer.wrap(bytes, locateKind(bytes), 4).int)
    }

    /**
     * Offset of the binding's big-endian kind integer, found without layout
     * assumptions: encode the same manifest with a different kind and diff.
     * Kinds 6 and 0 differ only in the integer's low byte, which is its 4th byte.
     */
    private fun locateKind(reference: ByteArray): Int {
        val other = ManifestCanonicalizer.canonicalBytes(manifestWith(TransportKind.AMNEZIA_WG))
        assertEquals(reference.size, other.size)
        val diffs = reference.indices.filter { reference[it] != other[it] }
        assertEquals("exactly one differing byte expected", 1, diffs.size)
        return diffs.single() - 3
    }

    @Test
    fun `an unknown wire id still rejects the whole manifest - fail-closed until a tolerant schema-2 decoder exists`() {
        val bytes = ManifestCanonicalizer.canonicalBytes(manifestWith(TransportKind.XRAY_REALITY_XHTTP))
        val offset = locateKind(bytes)
        listOf(7, 99, -1, Int.MAX_VALUE).forEach { unknown ->
            val tampered = bytes.copyOf()
            java.nio.ByteBuffer.wrap(tampered, offset, 4).putInt(unknown)
            val error = runCatching { ManifestCanonicalizer.decode(tampered) }.exceptionOrNull()
            assertTrue("wire id $unknown must be rejected, got $error", error is IllegalArgumentException)
        }
    }
}
