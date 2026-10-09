package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

/**
 * A server that adds a TransportKind after an APK was built must not make
 * that APK reject the whole signed manifest (it would then sit on its
 * last-known-good copy until it expires). Unknown kinds are kept opaque so
 * the signature still verifies, and are never usable.
 */
class ManifestForwardCompatibilityTest {

    private val priv = Ed25519PrivateKeyParameters(SecureRandom())
    private val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to priv.generatePublicKey().encoded))

    private fun sign(bytes: ByteArray): ByteArray = Ed25519Signer().run {
        init(true, priv)
        update(bytes, 0, bytes.size)
        generateSignature()
    }

    /** What a newer server would sign: a known AWG binding plus kinds this build has never heard of. */
    private fun newerServerManifest() = EndpointManifest(
        manifestVersion = 9,
        issuedAtEpochMillis = 1_000_000L,
        expiresAtEpochMillis = 2_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("frankfurt"), setOf(EndpointRole.GATEWAY), "DE", "test",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "152.70.43.1", 51820)),
                opaqueTransports = listOf(OpaqueTransportBinding(42, "152.70.43.1", 8443, mapOf("future" to "yes"))),
            ),
            EndpointDescriptor(
                EndpointId("future-only"), setOf(EndpointRole.GATEWAY), "SE", "test",
                transports = emptyList(),
                opaqueTransports = listOf(OpaqueTransportBinding(43, "16.170.208.231", 9443)),
            ),
        ),
    )

    @Test
    fun `a manifest with unknown transport kinds decodes, verifies, and re-encodes to the signed bytes`() {
        val signedBytes = ManifestCanonicalizer.canonicalBytes(newerServerManifest())
        val wire = SignedManifestCodec.encode(SignedManifest(ManifestCanonicalizer.decode(signedBytes), sign(signedBytes)))

        val received = SignedManifestCodec.decode(wire)

        assertEquals(ManifestVerificationResult.Valid, Ed25519ManifestVerifier().verify(received, anchors, nowEpochMillis = 1_500_000L))
        assertArrayEquals(signedBytes, ManifestCanonicalizer.canonicalBytes(received.manifest))
    }

    @Test
    fun `unknown kinds are never usable - only known bindings are exposed`() {
        val decoded = ManifestCanonicalizer.decode(ManifestCanonicalizer.canonicalBytes(newerServerManifest()))
        val frankfurt = decoded.endpoints.single { it.id.value == "frankfurt" }
        val futureOnly = decoded.endpoints.single { it.id.value == "future-only" }

        assertEquals(listOf(TransportKind.AMNEZIA_WG), frankfurt.transports.map { it.kind })
        assertEquals(listOf(42), frankfurt.opaqueTransports.map { it.kindOrdinal })
        assertTrue(futureOnly.transports.isEmpty())
        TransportKind.entries.forEach { assertFalse(futureOnly.supports(it)) }
    }

    @Test
    fun `tampering with an opaque binding still breaks the signature`() {
        val signedBytes = ManifestCanonicalizer.canonicalBytes(newerServerManifest())
        val signature = sign(signedBytes)
        val decoded = ManifestCanonicalizer.decode(signedBytes)
        val tampered = decoded.copy(
            endpoints = decoded.endpoints.map { e ->
                e.copy(opaqueTransports = e.opaqueTransports.map { it.copy(port = it.port + 1) })
            },
        )

        val result = Ed25519ManifestVerifier().verify(SignedManifest(tampered, signature), anchors, nowEpochMillis = 1_500_000L)

        assertTrue(result != ManifestVerificationResult.Valid)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `a known kind can never be smuggled in as opaque`() {
        EndpointDescriptor(
            EndpointId("gw"), setOf(EndpointRole.GATEWAY), "DE", "test",
            transports = emptyList(),
            opaqueTransports = listOf(OpaqueTransportBinding(TransportKind.AMNEZIA_WG.ordinal, "203.0.113.1", 51820)),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun `the same unknown kind twice on one endpoint is rejected`() {
        EndpointDescriptor(
            EndpointId("gw"), setOf(EndpointRole.GATEWAY), "DE", "test",
            transports = emptyList(),
            opaqueTransports = listOf(OpaqueTransportBinding(42, "a", 1), OpaqueTransportBinding(42, "b", 2)),
        )
    }

    /**
     * Signed manifests encode TransportKind by ORDINAL (ManifestCanonicalizer).
     * Reordering, renaming into a different slot or inserting in the middle
     * would silently change what every deployed manifest means. Append only.
     */
    @Test
    fun `TransportKind ordinals are append-only wire ids`() {
        assertEquals(
            listOf("AMNEZIA_WG", "XRAY_REALITY", "QUIC", "TLS_TCP", "XRAY_XHTTP", "SHADOWSOCKS_2022", "HYSTERIA2"),
            TransportKind.entries.map { it.name },
        )
    }

    /** Every production manifest ever signed (gateway/tools) must still decode byte-for-byte, with nothing opaque. */
    @Test
    fun `every committed production manifest still round-trips to its signed bytes`() {
        var dir: java.io.File? = java.io.File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !java.io.File(dir, "gateway/tools").isDirectory) dir = dir.parentFile
        val tools = java.io.File(requireNotNull(dir) { "repository root not found" }, "gateway/tools")
        val artifacts = tools.listFiles { f -> f.name.startsWith("endpoint-manifest-") && f.name.endsWith(".bin") }!!.sortedBy { it.name }
        assertTrue("expected the committed v1-v7 artifacts", artifacts.size >= 7)
        artifacts.forEach { file ->
            val bytes = file.readBytes()
            val input = java.io.DataInputStream(bytes.inputStream())
            input.readInt() // container format version
            val canonical = ByteArray(input.readInt()).also { input.readFully(it) }
            val manifest = SignedManifestCodec.decode(bytes).manifest

            assertArrayEquals(file.name, canonical, ManifestCanonicalizer.canonicalBytes(manifest))
            assertTrue(file.name, manifest.endpoints.all { it.opaqueTransports.isEmpty() })
        }
    }
}
