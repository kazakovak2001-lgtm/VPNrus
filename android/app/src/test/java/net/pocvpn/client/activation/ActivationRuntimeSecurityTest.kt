package net.pocvpn.client.activation

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * B56-5 - structural guarantees for the runtime (main source set): the
 * app only ever VERIFIES activation envelopes; no signing primitive, no
 * private key material and no operator secret path exist in shipped code.
 */
class ActivationRuntimeSecurityTest {
    private fun mainSources(): File {
        // Gradle runs unit tests with user.dir = the module dir; walk up so
        // any working directory inside the checkout resolves the same tree.
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            listOf("src/main/java/net/pocvpn/client", "android/app/src/main/java/net/pocvpn/client")
                .map { File(dir, it) }.firstOrNull { it.isDirectory }?.let { return it }
            dir = dir.parentFile
        }
        error("main source set not found from ${System.getProperty("user.dir")}")
    }

    @Test fun `no Ed25519 private key or signing mode anywhere in runtime sources`() {
        val offenders = mainSources().walkTopDown().filter { it.extension == "kt" }.filter { file ->
            val text = file.readText()
            text.contains("Ed25519PrivateKeyParameters") || text.contains(".init(true") || text.contains(".nova-secrets")
        }.map { it.name }.toList()
        assertEquals(emptyList<String>(), offenders)
    }

    @Test fun `production activation anchor is a single 32-byte public key under the r2 key id`() {
        val key = ProductionActivationIssuerTrustAnchors.trustAnchors()
            .publicKeyFor(ActivationIssuerKeyId(ProductionActivationIssuerTrustAnchors.PRIMARY_KEY_ID))
        assertEquals("prod-activation-issuer-2026-09-20-r2", ProductionActivationIssuerTrustAnchors.PRIMARY_KEY_ID)
        assertEquals(32, key!!.size)
    }

    @Test fun `package importer only accepts activation-issuer anchors, a type disjoint from manifest anchors`() {
        val param = ActivationPackageImporter::class.java.declaredConstructors.flatMap { it.parameterTypes.toList() }
        assertTrue(param.contains(ActivationIssuerTrustAnchors::class.java))
        assertTrue(param.none { it.name.endsWith("ManifestTrustAnchors") })
        assertTrue(!ActivationIssuerTrustAnchors::class.java.isAssignableFrom(net.pocvpn.client.reachability.ManifestTrustAnchors::class.java))
    }
}
