package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * gateway/DEPLOYMENT.md "REALITY + XHTTP on Stockholm", rollback B: once a
 * device adopted v9 it rejects v8, so the rollback is a v10 carrying v8's
 * endpoints. Runs the REAL [EndpointManifestRepository] + [Ed25519ManifestVerifier]
 * + [FileLastKnownGoodManifestStore] over the Python-signed fixtures from
 * gateway/tools/tests/manifest_rollback_fixtures.py.
 *
 * Proves: v9/v10 CONTENT (the committed v9 draft JSON, v10 derived from v8),
 * signature verification, expiry/issuedAt acceptance, and rollback
 * monotonicity. Does NOT prove a production signature: the fixtures are
 * signed with the TEST key bytes 0..31, mapped here to the production key
 * ids. That the app trusts those ids is checked separately against
 * [EmbeddedBootstrapManifest.trustAnchors].
 */
class RealityXhttpManifestRollbackChainTest {
    @get:Rule val tmp = TemporaryFolder()

    private val fixtures: File = run {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null && !File(dir, "gateway/tools").isDirectory) dir = dir.parentFile
        File(requireNotNull(dir) { "repository root not found" }, "gateway/tools/tests/fixtures/manifest-rollback")
    }

    private fun load(name: String) = SignedManifestCodec.decode(File(fixtures, "test-key-$name.bin").readBytes())

    private val v8 = load("v8")
    private val v9 = load("v9")
    private val v10 = load("v10")

    private val testPublicKey = Ed25519PrivateKeyParameters(ByteArray(32) { it.toByte() }, 0).generatePublicKey().encoded
    private val anchors = FixedManifestTrustAnchors(
        listOf(v8, v9, v10).associate { TrustedKeyId(it.manifest.signingKeyId) to testPublicKey },
    )
    private val now = v10.manifest.issuedAtEpochMillis + 3_600_000L

    private fun repository() = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
        bootstrapManifest = v8,
        nowEpochMillis = { now },
    )

    private fun EndpointManifest.xhttp() =
        endpoints.flatMap { it.transports }.filter { it.kind == TransportKind.XRAY_REALITY_XHTTP }

    private fun ManifestUpdateResult.isRollbackRejection() =
        this is ManifestUpdateResult.Rejected && kind == ManifestUpdateRejectionKind.ROLLBACK_OR_NOT_NEWER

    @Test
    fun `every fixture verifies with the real client verifier at the test clock`() {
        listOf(v8, v9, v10).forEach {
            assertEquals(ManifestVerificationResult.Valid::class, Ed25519ManifestVerifier().verify(it, anchors, now)::class)
        }
    }

    @Test
    fun `a single flipped signature byte is rejected`() {
        val tampered = v9.copy(signature = v9.signature.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertTrue(Ed25519ManifestVerifier().verify(tampered, anchors, now) is ManifestVerificationResult.Invalid)
        assertTrue(repository().offer(tampered) is ManifestUpdateResult.Rejected)
    }

    @Test
    fun `v8 to v9 to v10 rollback chain`() {
        val repo = repository()
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
        assertEquals(8, repo.trusted()!!.manifestVersion)

        assertTrue(repo.offer(v9) is ManifestUpdateResult.Accepted)
        val adopted9 = repo.trusted()!!
        assertEquals(9, adopted9.manifestVersion)
        assertEquals(listOf("16.170.208.231" to 2096), adopted9.xhttp().map { it.host to it.port })
        assertTrue(adopted9.endpoints.all { it.opaqueTransports.isEmpty() })

        assertTrue(repo.offer(v8).isRollbackRejection())
        assertEquals(9, repo.trusted()!!.manifestVersion)

        assertTrue(repo.offer(v10) is ManifestUpdateResult.Accepted)
        val adopted10 = repo.trusted()!!
        assertEquals(10, adopted10.manifestVersion)
        assertEquals(v8.manifest.endpoints, adopted10.endpoints)
        assertTrue(adopted10.xhttp().isEmpty())

        assertTrue(repo.offer(v9).isRollbackRejection())
        assertEquals(10, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `the production app trusts every signing key id the chain uses`() {
        val production = EmbeddedBootstrapManifest.trustAnchors()
        listOf(v8, v9, v10).forEach {
            assertTrue(it.manifest.signingKeyId, production.publicKeyFor(TrustedKeyId(it.manifest.signingKeyId)) != null)
        }
    }
}
