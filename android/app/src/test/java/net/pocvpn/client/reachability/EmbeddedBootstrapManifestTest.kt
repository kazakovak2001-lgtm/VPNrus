package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmbeddedBootstrapManifestTest {

    @Test
    fun `the embedded bootstrap manifest verifies against its own embedded trust anchors`() {
        val signed = EmbeddedBootstrapManifest.signedManifest()
        val result = Ed25519ManifestVerifier().verify(signed, EmbeddedBootstrapManifest.trustAnchors(), signed.manifest.issuedAtEpochMillis + 1)
        assertEquals(ManifestVerificationResult.Valid, result)
    }

    @Test
    fun `the embedded bootstrap manifest names at least one real endpoint with a real transport binding`() {
        val manifest = EmbeddedBootstrapManifest.signedManifest().manifest
        assertTrue(manifest.endpoints.isNotEmpty())
        val gateway = manifest.endpoints.first()
        assertTrue(gateway.supports(TransportKind.AMNEZIA_WG))
    }

    /** B17 - the production bootstrap must name BOTH real production gateways, not just one. */
    @Test
    fun `the production embedded bootstrap names both Germany and Stockholm`() {
        val manifest = EmbeddedBootstrapManifest.signedManifest().manifest
        val ids = manifest.endpoints.map { it.id.value }.toSet()
        assertEquals(setOf("frankfurt", "stockholm"), ids)
        manifest.endpoints.forEach { endpoint ->
            assertTrue(endpoint.supports(TransportKind.AMNEZIA_WG))
            assertTrue(endpoint.supports(TransportKind.XRAY_REALITY))
            assertTrue(endpoint.supports(TransportKind.TLS_TCP))
        }
    }

    /** B17 - no per-device secret ever leaks into the embedded bootstrap's metadata. */
    @Test
    fun `the production embedded bootstrap carries no per-device or credential metadata`() {
        val manifest = EmbeddedBootstrapManifest.signedManifest().manifest
        manifest.endpoints.forEach { endpoint ->
            endpoint.transports.forEach { binding -> assertTrue(binding.metadata.isEmpty()) }
        }
    }
}
