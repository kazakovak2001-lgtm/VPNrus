package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

class EndpointManifestRepositoryTest {

    @get:Rule val tempFolder = TemporaryFolder()

    private val random = SecureRandom()
    private val priv = Ed25519PrivateKeyParameters(random)
    private val pub = priv.generatePublicKey().encoded
    private val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId("key-1") to pub))

    private fun sign(manifest: EndpointManifest): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return SignedManifest(manifest, signer.generateSignature())
    }

    private fun manifest(version: Int, issuedAt: Long = 1_000L, expiresAt: Long = 9_000_000L) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = issuedAt,
        expiresAtEpochMillis = expiresAt,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw"),
                setOf(EndpointRole.GATEWAY),
                "eu",
                "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
            ),
        ),
    )

    private fun bootstrap() = sign(manifest(version = 1))

    private fun repository(store: LastKnownGoodManifestStore, now: Long = 2_000L) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = store,
        bootstrapManifest = bootstrap(),
        nowEpochMillis = { now },
    )

    @Test
    fun `with no LKG stored, trusted() returns the embedded bootstrap`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        assertEquals(1, repo.trusted().manifestVersion)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `a newer valid manifest replaces the LKG and becomes trusted`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        val candidate = sign(manifest(version = 2))
        val result = repo.offer(candidate)
        assertTrue(result is ManifestUpdateResult.Accepted)
        assertEquals(2, repo.trusted().manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `version rollback is rejected and LKG is untouched`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Accepted)
        val rollback = repo.offer(sign(manifest(version = 2)))
        assertTrue(rollback is ManifestUpdateResult.Rejected)
        assertEquals(3, repo.trusted().manifestVersion)
    }

    @Test
    fun `an equal version is rejected as a rollback, not silently re-accepted`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Accepted)
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Rejected)
    }

    @Test
    fun `an invalid newer manifest (bad signature) does NOT replace the LKG`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        assertTrue(repo.offer(sign(manifest(version = 2))) is ManifestUpdateResult.Accepted)

        val (otherPriv, _) = Ed25519PrivateKeyParameters(random).let { it to it.generatePublicKey().encoded }
        val forged = manifest(version = 5)
        val forgedSigner = Ed25519Signer().apply { init(true, otherPriv) }
        val bytes = ManifestCanonicalizer.canonicalBytes(forged)
        forgedSigner.update(bytes, 0, bytes.size)
        val badSigned = SignedManifest(forged, forgedSigner.generateSignature())

        val result = repo.offer(badSigned)
        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(2, repo.trusted().manifestVersion)
    }

    @Test
    fun `an expired newer manifest does NOT replace the LKG`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store, now = 20_000_000L)
        val expired = sign(manifest(version = 9, issuedAt = 1_000L, expiresAt = 9_000_000L))
        val result = repo.offer(expired)
        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `LKG persists across a simulated app restart (new store instance, same directory)`() {
        val dir = tempFolder.newFolder()
        val store1 = FileLastKnownGoodManifestStore(dir)
        val repo1 = repository(store1)
        repo1.offer(sign(manifest(version = 4)))

        val store2 = FileLastKnownGoodManifestStore(dir)
        val repo2 = repository(store2)
        assertEquals(4, repo2.trusted().manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo2.trustedSource())
    }

    @Test
    fun `a corrupted LKG file on disk is treated as absent, not a crash`() {
        val dir = tempFolder.newFolder()
        java.io.File(dir, "endpoint_manifest_lkg.bin").writeBytes(byteArrayOf(1, 2, 3))
        val store = FileLastKnownGoodManifestStore(dir)
        assertEquals(null, store.current())
    }

    @Test
    fun `ManifestRollbackGuard is a pure, standalone check`() {
        assertTrue(ManifestRollbackGuard.isAcceptableReplacement(null, manifest(version = 1)))
        assertTrue(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 1), manifest(version = 2)))
        assertFalse(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 2), manifest(version = 2)))
        assertFalse(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 3), manifest(version = 2)))
    }
}
