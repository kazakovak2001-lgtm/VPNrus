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
}
