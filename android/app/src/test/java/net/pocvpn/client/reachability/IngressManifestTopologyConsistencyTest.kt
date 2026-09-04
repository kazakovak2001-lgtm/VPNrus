package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B31 - proves the manifest wire format itself (ManifestCanonicalizer,
 * shared by the embedded bootstrap and any future signed production
 * manifest refresh) already round-trips an INGRESS/relayTo/IngressKind
 * topology byte-for-byte, with no schema change required - and that an
 * invalid/incomplete relay topology in that data still fails closed rather
 * than producing a misleading relayed candidate. Uses the SAME plain
 * encode/decode round-trip style SignedManifestCodecTest already uses
 * (signature bytes are opaque to this layer - see that file) - never the
 * production private key, which this test suite has no access to and
 * should not.
 */
class IngressManifestTopologyConsistencyTest {

    private val stockholmIngress = EndpointDescriptor(
        id = EndpointId("stockholm-ingress-1"),
        roles = setOf(EndpointRole.INGRESS),
        region = "Sweden / Stockholm",
        provider = "AWS",
        transports = listOf(
            EndpointTransportBinding(TransportKind.XRAY_REALITY, "16.170.208.231", 2093).withIngressKind(IngressKind.DIRECT_IP),
        ),
        relayTo = EndpointId("frankfurt"),
    )

    private val germanyExit = EndpointDescriptor(
        id = EndpointId("frankfurt"),
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "Germany / Frankfurt",
        provider = "Oracle Cloud",
        transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 2053)),
    )

    private fun manifestWith(vararg endpoints: EndpointDescriptor) = EndpointManifest(
        manifestVersion = 1,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 2_000L,
        signingKeyId = "test-key",
        endpoints = endpoints.toList(),
    )

    // --- 9: signed/remote manifest parse+merge (the shared canonical wire format) preserves the ingress topology ---

    @Test
    fun `ManifestCanonicalizer round-trips the Stockholm-ingress-to-Germany-exit topology byte-for-byte`() {
        val manifest = manifestWith(stockholmIngress, germanyExit)
        val decoded = ManifestCanonicalizer.decode(ManifestCanonicalizer.canonicalBytes(manifest))
        // ManifestCanonicalizer sorts endpoints by id for determinism (see
        // its own docs) - compare as sets, the same discipline the
        // canonicalizer itself already applies to roles/transports/metadata.
        assertEquals(manifest.copy(endpoints = manifest.endpoints.sortedBy { it.id.value }), decoded)
        assertEquals(manifest.endpoints.toSet(), decoded.endpoints.toSet())

        val decodedIngress = decoded.endpoints.single { it.id == stockholmIngress.id }
        assertEquals(setOf(EndpointRole.INGRESS), decodedIngress.roles)
        assertEquals(EndpointId("frankfurt"), decodedIngress.relayTo)
        assertEquals(IngressKind.DIRECT_IP, decodedIngress.bindingFor(TransportKind.XRAY_REALITY)!!.ingressKind())
        assertEquals(2093, decodedIngress.bindingFor(TransportKind.XRAY_REALITY)!!.port)
    }

    @Test
    fun `SignedManifestCodec round-trips a SignedManifest carrying the ingress topology unchanged`() {
        // SignedManifestCodec is a byte-container codec, not the canonicalizer -
        // it never reorders endpoints, so listing them already in the
        // canonicalizer's own sorted-by-id order keeps this a pure identity check.
        val signed = SignedManifest(manifestWith(germanyExit, stockholmIngress), byteArrayOf(9, 9, 9, 9))
        val decoded = SignedManifestCodec.decode(SignedManifestCodec.encode(signed))
        assertEquals(signed, decoded)
    }

    // --- 10: invalid/incomplete relay topology fails closed, never a misleading relayed candidate ---

    private fun reach(id: EndpointId, kind: TransportKind) = EndpointReachability(
        id, kind, ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(net.pocvpn.client.transport.TransportHealthState.HEALTHY, 0, true, true, net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN),
    )

    @Test
    fun `an ingress with no relayTo target never yields a Relayed candidate`() {
        val orphanIngress = stockholmIngress.copy(relayTo = null)
        val candidate = PathCandidateBuilder.buildRelayed(
            orphanIngress, germanyExit, TransportKind.XRAY_REALITY, TransportKind.XRAY_REALITY,
            reach(orphanIngress.id, TransportKind.XRAY_REALITY), reach(germanyExit.id, TransportKind.XRAY_REALITY),
        )
        assertNull(candidate)
    }

    @Test
    fun `an ingress whose relayTo names an id absent from the endpoint set never yields a Relayed candidate`() {
        // The manifest's own init{} already rejects a relayTo to an unknown
        // id at construction time (fail closed as early as possible) - this
        // proves the SAME discipline holds one level down, at
        // PathCandidateBuilder itself, for a caller resolving hops directly.
        val danglingIngress = stockholmIngress.copy(relayTo = EndpointId("no-such-exit"))
        val candidate = PathCandidateBuilder.buildRelayed(
            danglingIngress, germanyExit, TransportKind.XRAY_REALITY, TransportKind.XRAY_REALITY,
            reach(danglingIngress.id, TransportKind.XRAY_REALITY), reach(germanyExit.id, TransportKind.XRAY_REALITY),
        )
        assertNull(candidate)
    }

    @Test
    fun `constructing a manifest whose relayTo names an unknown endpoint fails closed at construction, not silently`() {
        assertTrue(
            runCatching { manifestWith(stockholmIngress.copy(relayTo = EndpointId("ghost")), germanyExit) }.isFailure,
        )
    }

    @Test
    fun `an endpoint declared EXIT-only can never itself be mistaken for an ingress entrypoint`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            germanyExit, germanyExit, TransportKind.XRAY_REALITY, TransportKind.XRAY_REALITY,
            reach(germanyExit.id, TransportKind.XRAY_REALITY), reach(germanyExit.id, TransportKind.XRAY_REALITY),
        )
        assertNull(candidate)
    }
}
