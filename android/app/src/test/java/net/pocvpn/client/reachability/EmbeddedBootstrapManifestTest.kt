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
}
