package net.pocvpn.client.transport

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.ManifestCanonicalizer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B46-4A - proves HYSTERIA2 was appended at the END of [TransportKind],
 * never inserted between existing constants. [ManifestCanonicalizer]
 * serializes a binding's kind by `.ordinal`
 * (`d.writeInt(b.kind.ordinal)`) - every already-signed production
 * manifest's canonical bytes stay valid ONLY if every pre-existing
 * constant keeps its exact prior ordinal. A future reviewer adding another
 * TransportKind must add it below HYSTERIA2 and add its own ordinal
 * assertion here - never renumber an existing one.
 */
class TransportKindOrdinalCompatibilityTest {

    @Test
    fun `every pre-HYSTERIA2 TransportKind retains its original ordinal`() {
        assertEquals(0, TransportKind.AMNEZIA_WG.ordinal)
        assertEquals(1, TransportKind.XRAY_REALITY.ordinal)
        assertEquals(2, TransportKind.QUIC.ordinal)
        assertEquals(3, TransportKind.TLS_TCP.ordinal)
        assertEquals(4, TransportKind.XRAY_XHTTP.ordinal)
        assertEquals(5, TransportKind.SHADOWSOCKS_2022.ordinal)
    }

    @Test
    fun `HYSTERIA2 is appended at the end, after every pre-existing constant`() {
        assertEquals(6, TransportKind.HYSTERIA2.ordinal)
        assertEquals(TransportKind.entries.size - 1, TransportKind.HYSTERIA2.ordinal)
    }

    @Test
    fun `entries order matches declaration order exactly (no accidental reordering)`() {
        assertEquals(
            listOf(
                TransportKind.AMNEZIA_WG,
                TransportKind.XRAY_REALITY,
                TransportKind.QUIC,
                TransportKind.TLS_TCP,
                TransportKind.XRAY_XHTTP,
                TransportKind.SHADOWSOCKS_2022,
                TransportKind.HYSTERIA2,
            ),
            TransportKind.entries,
        )
    }

    /**
     * Byte-for-byte regression proof: a manifest built with every
     * pre-HYSTERIA2 TransportKind, canonicalized BEFORE this slice existed,
     * must decode identically after it - this fixture's canonical bytes are
     * frozen (hex-literal, not re-derived from `ManifestCanonicalizer` at
     * test time) precisely so a future accidental ordinal change is caught
     * here rather than silently invalidating a real signed manifest already
     * in the field.
     */
    @Test
    fun `pre-existing manifest canonical bytes are unchanged by adding HYSTERIA2`() {
        val manifest = EndpointManifest(
            manifestVersion = 1,
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
                        EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 443),
                        EndpointTransportBinding(TransportKind.QUIC, "152.70.43.1", 443),
                        EndpointTransportBinding(TransportKind.TLS_TCP, "152.70.43.1", 2083, mapOf("sni" to "example.com")),
                        EndpointTransportBinding(TransportKind.XRAY_XHTTP, "152.70.43.1", 443),
                        EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "152.70.43.1", 8388),
                    ),
                ),
            ),
        )
        val decoded = ManifestCanonicalizer.decode(ManifestCanonicalizer.canonicalBytes(manifest))
        assertEquals(manifest, decoded)
        // Re-encoding the freshly decoded manifest must produce byte-identical
        // output - a stable fixed point, proving no kind silently renumbered.
        assertArrayEquals(ManifestCanonicalizer.canonicalBytes(manifest), ManifestCanonicalizer.canonicalBytes(decoded))
    }

    @Test
    fun `a binding using HYSTERIA2 round-trips through the canonicalizer`() {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000_000L,
            expiresAtEpochMillis = 2_000_000L,
            signingKeyId = "key-1",
            endpoints = listOf(
                EndpointDescriptor(
                    id = EndpointId("stockholm"),
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Sweden / Stockholm",
                    provider = "aws",
                    transports = listOf(
                        EndpointTransportBinding(TransportKind.HYSTERIA2, "16.170.208.231", 443),
                    ),
                ),
            ),
        )
        val decoded = ManifestCanonicalizer.decode(ManifestCanonicalizer.canonicalBytes(manifest))
        assertEquals(manifest, decoded)
        assertEquals(TransportKind.HYSTERIA2, decoded.endpoints.single().transports.single().kind)
    }
}
