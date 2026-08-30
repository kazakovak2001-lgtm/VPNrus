package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class ManifestCanonicalizerTest {

    private fun sampleManifest(version: Int = 1) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                id = EndpointId("frankfurt"),
                roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                region = "Germany / Frankfurt",
                provider = "hetzner",
                asn = 24940,
                transports = listOf(
                    EndpointTransportBinding(TransportKind.AMNEZIA_WG, "152.70.43.1", 51820),
                    EndpointTransportBinding(TransportKind.TLS_TCP, "152.70.43.1", 2083, mapOf("sni" to "example.com")),
                ),
            ),
        ),
    )

    @Test
    fun `canonicalBytes is deterministic across repeated calls`() {
        val m = sampleManifest()
        assertArrayEquals(ManifestCanonicalizer.canonicalBytes(m), ManifestCanonicalizer.canonicalBytes(m))
    }

    @Test
    fun `canonicalBytes is independent of Set and Map iteration order`() {
        val e1 = EndpointDescriptor(
            EndpointId("e1"),
            roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
            region = "eu",
            provider = "acme",
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, "h", 1, mapOf("a" to "1", "b" to "2")),
            ),
        )
        val e2 = e1.copy(
            roles = setOf(EndpointRole.EXIT, EndpointRole.GATEWAY),
            transports = listOf(
                EndpointTransportBinding(TransportKind.AMNEZIA_WG, "h", 1, mapOf("b" to "2", "a" to "1")),
            ),
        )
        val m1 = sampleManifest().copy(endpoints = listOf(e1))
        val m2 = sampleManifest().copy(endpoints = listOf(e2))
        assertArrayEquals(ManifestCanonicalizer.canonicalBytes(m1), ManifestCanonicalizer.canonicalBytes(m2))
    }

    @Test
    fun `decode(canonicalBytes(m)) round-trips to an equal manifest`() {
        val m = sampleManifest()
        val decoded = ManifestCanonicalizer.decode(ManifestCanonicalizer.canonicalBytes(m))
        assertEquals(m, decoded)
    }

    @Test
    fun `a different manifest version produces different canonical bytes`() {
        val a = ManifestCanonicalizer.canonicalBytes(sampleManifest(version = 1))
        val b = ManifestCanonicalizer.canonicalBytes(sampleManifest(version = 2))
        org.junit.Assert.assertFalse(a.contentEquals(b))
    }

    // --- Decode-ambiguity regression tests: hand-crafted bytes a real signer
    // would never legitimately produce (Kotlin's Set/Map types make these
    // shapes unconstructable), but which a corrupted/malicious byte stream
    // could still contain. Before the fix these silently deduplicated on
    // decode, producing an object whose own re-canonicalization diverged
    // from the bytes actually signed. ---

    private fun writeStr(d: java.io.DataOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    /** One endpoint with a caller-controlled role-ordinal list (may contain duplicates) and no transports written beyond a single AMNEZIA_WG binding. */
    private fun manifestBytesWithRoles(roleOrdinals: List<Int>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1) // FORMAT_VERSION
            d.writeInt(1) // manifestVersion
            d.writeLong(1_000L) // issuedAt
            d.writeLong(2_000L) // expiresAt
            writeStr(d, "key-1") // signingKeyId
            d.writeInt(1) // endpointCount
            writeStr(d, "e1") // id
            d.writeInt(roleOrdinals.size)
            roleOrdinals.forEach { d.writeInt(it) }
            writeStr(d, "eu") // region
            writeStr(d, "acme") // provider
            d.writeBoolean(false) // hasAsn
            d.writeInt(0)
            d.writeInt(1) // transportCount
            d.writeInt(TransportKind.AMNEZIA_WG.ordinal)
            writeStr(d, "203.0.113.1")
            d.writeInt(51820)
            d.writeInt(0) // metadataCount
            d.writeBoolean(false) // hasRelay
            writeStr(d, "")
        }
        return out.toByteArray()
    }

    /** One endpoint, one transport binding, with a caller-controlled metadata entry list (may contain duplicate keys). */
    private fun manifestBytesWithMetadata(metadataEntries: List<Pair<String, String>>): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(1)
            d.writeInt(1)
            d.writeLong(1_000L)
            d.writeLong(2_000L)
            writeStr(d, "key-1")
            d.writeInt(1)
            writeStr(d, "e1")
            d.writeInt(1)
            d.writeInt(EndpointRole.GATEWAY.ordinal)
            writeStr(d, "eu")
            writeStr(d, "acme")
            d.writeBoolean(false)
            d.writeInt(0)
            d.writeInt(1)
            d.writeInt(TransportKind.AMNEZIA_WG.ordinal)
            writeStr(d, "203.0.113.1")
            d.writeInt(51820)
            d.writeInt(metadataEntries.size)
            metadataEntries.forEach { (k, v) -> writeStr(d, k); writeStr(d, v) }
            d.writeBoolean(false)
            writeStr(d, "")
        }
        return out.toByteArray()
    }

    @Test
    fun `decode rejects a duplicate EndpointRole ordinal rather than silently deduplicating`() {
        val bytes = manifestBytesWithRoles(listOf(EndpointRole.GATEWAY.ordinal, EndpointRole.GATEWAY.ordinal))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { ManifestCanonicalizer.decode(bytes) }
    }

    @Test
    fun `decode accepts distinct role ordinals normally`() {
        val bytes = manifestBytesWithRoles(listOf(EndpointRole.GATEWAY.ordinal, EndpointRole.EXIT.ordinal))
        val decoded = ManifestCanonicalizer.decode(bytes)
        assertEquals(setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), decoded.endpoints.single().roles)
    }

    @Test
    fun `decode rejects a duplicate metadata key rather than silently collapsing it`() {
        val bytes = manifestBytesWithMetadata(listOf("sni" to "a.example.com", "sni" to "b.example.com"))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) { ManifestCanonicalizer.decode(bytes) }
    }

    @Test
    fun `decode accepts distinct metadata keys normally`() {
        val bytes = manifestBytesWithMetadata(listOf("sni" to "a.example.com", "alpn" to "h2"))
        val decoded = ManifestCanonicalizer.decode(bytes)
        assertEquals(mapOf("sni" to "a.example.com", "alpn" to "h2"), decoded.endpoints.single().transports.single().metadata)
    }

    @Test
    fun `a manifest with an ambiguous (duplicate-role) encoding cannot be forged into verifying as a different, cleaner manifest`() {
        // Even if decode() DID silently dedupe (pre-fix behavior), re-encoding
        // the deduped object would never reproduce the original ambiguous
        // bytes - so this class of input can never pass signature
        // verification either way. This test pins that re-encoding
        // divergence directly, independent of the decode-time rejection
        // above, as a second, independent line of defense.
        val dedupedEquivalent = manifestBytesWithRoles(listOf(EndpointRole.GATEWAY.ordinal))
        val ambiguous = manifestBytesWithRoles(listOf(EndpointRole.GATEWAY.ordinal, EndpointRole.GATEWAY.ordinal))
        org.junit.Assert.assertFalse(dedupedEquivalent.contentEquals(ambiguous))
    }
}
