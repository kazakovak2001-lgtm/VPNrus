package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    private fun signWith(priv: Ed25519PrivateKeyParameters, manifest: EndpointManifest): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, priv)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return SignedManifest(manifest, signer.generateSignature())
    }

    private fun sign(manifest: EndpointManifest): SignedManifest = signWith(priv, manifest)

    private fun manifest(version: Int, issuedAt: Long = 1_000L, expiresAt: Long = 9_000_000L, keyId: String = "key-1") = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = issuedAt,
        expiresAtEpochMillis = expiresAt,
        signingKeyId = keyId,
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

    private fun repository(store: LastKnownGoodManifestStore, bootstrap: SignedManifest = bootstrap(), now: Long = 2_000L) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = store,
        bootstrapManifest = bootstrap,
        nowEpochMillis = { now },
    )

    private fun newStore() = FileLastKnownGoodManifestStore(tempFolder.newFolder())

    // --- LKG-present precedence (existing behavior, still correct under the new sealed trustedState()) ---

    @Test
    fun `with no LKG stored, a valid bootstrap is accepted and becomes trusted`() {
        val repo = repository(newStore())
        assertEquals(1, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
        assertTrue(repo.trustedState() is TrustedManifestState.Trusted)
    }

    @Test
    fun `a newer valid manifest replaces the LKG and becomes trusted`() {
        val repo = repository(newStore())
        val candidate = sign(manifest(version = 2))
        val result = repo.offer(candidate)
        assertTrue(result is ManifestUpdateResult.Accepted)
        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    @Test
    fun `version rollback is rejected and LKG is untouched`() {
        val repo = repository(newStore())
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Accepted)
        val rollback = repo.offer(sign(manifest(version = 2)))
        assertTrue(rollback is ManifestUpdateResult.Rejected)
        assertEquals(3, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `an equal version is rejected as a rollback, not silently re-accepted`() {
        val repo = repository(newStore())
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Accepted)
        assertTrue(repo.offer(sign(manifest(version = 3))) is ManifestUpdateResult.Rejected)
    }

    @Test
    fun `an invalid newer manifest (bad signature) does NOT replace the LKG`() {
        val repo = repository(newStore())
        assertTrue(repo.offer(sign(manifest(version = 2))) is ManifestUpdateResult.Accepted)

        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badSigned = signWith(otherPriv, manifest(version = 5))

        val result = repo.offer(badSigned)
        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `an expired newer manifest does NOT replace the LKG`() {
        val longLivedBootstrap = sign(manifest(version = 1, issuedAt = 1_000L, expiresAt = 100_000_000L))
        val repo = repository(newStore(), bootstrap = longLivedBootstrap, now = 20_000_000L)
        val expired = sign(manifest(version = 9, issuedAt = 1_000L, expiresAt = 9_000_000L))
        val result = repo.offer(expired)
        assertTrue(result is ManifestUpdateResult.Rejected)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `LKG persists across a simulated app restart (new store instance, same directory)`() {
        val dir = tempFolder.newFolder()
        val bootstrap = bootstrap()
        repository(FileLastKnownGoodManifestStore(dir), bootstrap).offer(sign(manifest(version = 4)))

        val repo2 = repository(FileLastKnownGoodManifestStore(dir), bootstrap)
        assertEquals(4, repo2.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo2.trustedSource())
    }

    @Test
    fun `a corrupted LKG file on disk is treated as absent, not a crash`() {
        val dir = tempFolder.newFolder()
        java.io.File(dir, "endpoint_manifest_lkg.bin").writeBytes(byteArrayOf(1, 2, 3))
        val store = FileLastKnownGoodManifestStore(dir)
        assertNull(store.current())
    }

    @Test
    fun `ManifestRollbackGuard is a pure, standalone check`() {
        assertTrue(ManifestRollbackGuard.isAcceptableReplacement(null, manifest(version = 1)))
        assertTrue(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 1), manifest(version = 2)))
        assertFalse(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 2), manifest(version = 2)))
        assertFalse(ManifestRollbackGuard.isAcceptableReplacement(manifest(version = 3), manifest(version = 2)))
    }

    // --- Bootstrap must be verified, not trusted merely for being embedded (PR #23 review fix) ---

    @Test
    fun `valid bootstrap (no LKG at all) is accepted and reported as EMBEDDED_BOOTSTRAP`() {
        val repo = repository(newStore(), bootstrap = bootstrap())
        val state = repo.trustedState()
        assertTrue(state is TrustedManifestState.Trusted)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, (state as TrustedManifestState.Trusted).source)
    }

    @Test
    fun `a bootstrap with a bad signature is rejected - fails closed, not silently used`() {
        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badBootstrap = signWith(otherPriv, manifest(version = 1)) // signed by a key NOT in anchors
        val repo = repository(newStore(), bootstrap = badBootstrap)

        val state = repo.trustedState()
        assertTrue(state is TrustedManifestState.NoneTrusted)
        assertNull(repo.trusted())
        assertNull(repo.trustedSource())
    }

    @Test
    fun `a bootstrap signed by an unknown key id is rejected`() {
        val unknownKeyBootstrap = sign(manifest(version = 1, keyId = "some-other-key"))
        val repo = repository(newStore(), bootstrap = unknownKeyBootstrap)

        assertTrue(repo.trustedState() is TrustedManifestState.NoneTrusted)
        assertNull(repo.trusted())
    }

    @Test
    fun `a tampered bootstrap (content changed after signing) is rejected`() {
        val signed = bootstrap()
        val tampered = signed.copy(manifest = signed.manifest.copy(manifestVersion = 99))
        val repo = repository(newStore(), bootstrap = tampered)

        assertTrue(repo.trustedState() is TrustedManifestState.NoneTrusted)
        assertNull(repo.trusted())
    }

    @Test
    fun `an expired bootstrap is rejected`() {
        val expiredBootstrap = sign(manifest(version = 1, issuedAt = 1_000L, expiresAt = 9_000_000L))
        val repo = repository(newStore(), bootstrap = expiredBootstrap, now = 20_000_000L)

        val state = repo.trustedState()
        assertTrue(state is TrustedManifestState.NoneTrusted)
        assertTrue((state as TrustedManifestState.NoneTrusted).bootstrapRejectionReason.contains("expired"))
    }

    @Test
    fun `a bootstrap issued too far in the future (beyond clock skew) is rejected`() {
        val now = 1_000_000L
        val futureBootstrap = sign(manifest(version = 1, issuedAt = now + 10_000_000L, expiresAt = now + 20_000_000L))
        val repo = repository(newStore(), bootstrap = futureBootstrap, now = now)

        val state = repo.trustedState()
        assertTrue(state is TrustedManifestState.NoneTrusted)
        assertTrue((state as TrustedManifestState.NoneTrusted).bootstrapRejectionReason.contains("future"))
    }

    @Test
    fun `invalid LKG plus a valid bootstrap falls back to the bootstrap correctly`() {
        val dir = tempFolder.newFolder()
        // Write a structurally-valid-looking LKG that was never actually verified -
        // simulates an on-disk file that fails verification (e.g. corrupted signature).
        val store = FileLastKnownGoodManifestStore(dir)
        val otherPriv = Ed25519PrivateKeyParameters(random)
        val invalidLkg = signWith(otherPriv, manifest(version = 7))
        store.store(invalidLkg) // stores unconditionally (rollback guard only, no signature check) - matches store's own docs

        val repo = repository(store, bootstrap = bootstrap())
        val state = repo.trustedState()
        assertTrue(state is TrustedManifestState.Trusted)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, (state as TrustedManifestState.Trusted).source)
        assertEquals(1, state.manifest.manifestVersion)
    }

    @Test
    fun `invalid LKG plus an invalid bootstrap fails closed with NoneTrusted`() {
        val dir = tempFolder.newFolder()
        val store = FileLastKnownGoodManifestStore(dir)
        val otherPriv = Ed25519PrivateKeyParameters(random)
        store.store(signWith(otherPriv, manifest(version = 7)))

        val badBootstrap = signWith(otherPriv, manifest(version = 1))
        val repo = repository(store, bootstrap = badBootstrap)

        assertTrue(repo.trustedState() is TrustedManifestState.NoneTrusted)
        assertNull(repo.trusted())
        assertNull(repo.trustedSource())
    }

    @Test
    fun `trustedSource never reports EMBEDDED_BOOTSTRAP for an invalid bootstrap`() {
        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badBootstrap = signWith(otherPriv, manifest(version = 1))
        val repo = repository(newStore(), bootstrap = badBootstrap)
        assertFalse(repo.trustedSource() == ManifestSource.EMBEDDED_BOOTSTRAP)
        assertNull(repo.trustedSource())
    }

    @Test
    fun `offer() against a NoneTrusted repository accepts any validly-signed non-expired candidate (nothing to roll back from)`() {
        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badBootstrap = signWith(otherPriv, manifest(version = 1))
        val repo = repository(newStore(), bootstrap = badBootstrap)
        assertTrue(repo.trustedState() is TrustedManifestState.NoneTrusted)

        val result = repo.offer(sign(manifest(version = 1)))
        assertTrue(result is ManifestUpdateResult.Accepted)
        assertEquals(1, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }
}
