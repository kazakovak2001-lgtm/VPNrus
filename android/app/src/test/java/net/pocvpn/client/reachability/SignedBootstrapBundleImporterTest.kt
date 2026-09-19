package net.pocvpn.client.reachability

import net.pocvpn.client.activation.ActivationIssuerKeyId
import net.pocvpn.client.activation.FixedActivationIssuerTrustAnchors
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

/**
 * B56-2 - proves the importer is a THIN relabeling boundary in front of the
 * real, unmodified [EndpointManifestRepository.offer]: every acceptance and
 * every rejection here is produced by the ACTUAL repository/verifier/
 * rollback-guard/LKG-store stack (no mocks of the trust boundary itself),
 * reusing [EndpointManifestRepositoryTest]'s own fixture shapes (B56-2's
 * architecture doc section 28 explicitly calls for this reuse).
 */
class SignedBootstrapBundleImporterTest {

    @get:Rule val tempFolder = TemporaryFolder()

    private val random = SecureRandom()
    private val priv = Ed25519PrivateKeyParameters(random)
    private val pub = priv.generatePublicKey().encoded
    private val privRotated = Ed25519PrivateKeyParameters(random)
    private val pubRotated = privRotated.generatePublicKey().encoded

    /** Two currently-trusted keys - mirrors the real embedded bootstrap's own two-key rotation window (case 7). */
    private val anchors = FixedManifestTrustAnchors(
        mapOf(
            TrustedKeyId("key-1") to pub,
            TrustedKeyId("key-2-rotated") to pubRotated,
        ),
    )

    private fun signWith(signingKey: Ed25519PrivateKeyParameters, manifest: EndpointManifest): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, signingKey)
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

    private fun newStore() = FileLastKnownGoodManifestStore(tempFolder.newFolder())

    private fun repository(store: LastKnownGoodManifestStore, bootstrap: SignedManifest = bootstrap(), now: Long = 2_000L) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = store,
        bootstrapManifest = bootstrap,
        nowEpochMillis = { now },
    )

    private fun importer(repository: EndpointManifestRepository) = SignedBootstrapBundleImporter(repository)

    // --- 1/11 - newer imported manifest accepted; NoneTrusted recovery ---

    @Test
    fun `a newer imported manifest is accepted, reports IMPORTED_SIGNED_BOOTSTRAP at import time, and becomes normal LKG`() {
        val repo = repository(newStore()) // trusted N = 1 (embedded bootstrap)
        val candidate = sign(manifest(version = 2))

        val result = importer(repo).import(candidate)

        assertTrue(result is BootstrapBundleImportResult.Accepted)
        result as BootstrapBundleImportResult.Accepted
        assertEquals(2, result.manifest.manifestVersion)
        assertEquals(ManifestSource.IMPORTED_SIGNED_BOOTSTRAP, result.source)

        // The durable, ongoing state is ordinary LKG - NOT a separate "imported" tier (case 4/16).
        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
        assertTrue((repo.trustedState() as TrustedManifestState.Trusted).source == ManifestSource.LAST_KNOWN_GOOD)
    }

    @Test
    fun `import when nothing is currently trusted (NoneTrusted) is accepted - nothing to roll back from`() {
        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badBootstrap = signWith(otherPriv, manifest(version = 1)) // embedded bootstrap fails verification
        val repo = repository(newStore(), bootstrap = badBootstrap)
        assertTrue(repo.trustedState() is TrustedManifestState.NoneTrusted)

        val result = importer(repo).import(sign(manifest(version = 1)))

        assertTrue(result is BootstrapBundleImportResult.Accepted)
        assertEquals(1, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    // --- 2/3 - same/older version rejected as rollback, LKG untouched ---

    @Test
    fun `an imported manifest at the same version as currently trusted is rejected as a rollback`() {
        val repo = repository(newStore())
        assertTrue(importer(repo).import(sign(manifest(version = 5))) is BootstrapBundleImportResult.Accepted)

        val result = importer(repo).import(sign(manifest(version = 5)))

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(5, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `an older imported manifest is rejected as a rollback, LKG unchanged`() {
        val repo = repository(newStore())
        assertTrue(importer(repo).import(sign(manifest(version = 5))) is BootstrapBundleImportResult.Accepted)

        val result = importer(repo).import(sign(manifest(version = 4)))

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(5, repo.trusted()!!.manifestVersion)
    }

    // --- 4/5/6 - expired / bad signature / unknown key, all rejected, LKG untouched ---

    @Test
    fun `an expired imported manifest is rejected, LKG unchanged`() {
        val longLivedBootstrap = sign(manifest(version = 1, issuedAt = 1_000L, expiresAt = 100_000_000L))
        val repo = repository(newStore(), bootstrap = longLivedBootstrap, now = 20_000_000L)

        val expired = sign(manifest(version = 9, issuedAt = 1_000L, expiresAt = 9_000_000L))
        val result = importer(repo).import(expired)

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_EXPIRED, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `an imported manifest with an invalid signature is rejected, LKG unchanged`() {
        val repo = repository(newStore())
        assertTrue(importer(repo).import(sign(manifest(version = 2))) is BootstrapBundleImportResult.Accepted)

        val otherPriv = Ed25519PrivateKeyParameters(random)
        val badSigned = signWith(otherPriv, manifest(version = 5)) // wrong key for signingKeyId "key-1"

        val result = importer(repo).import(badSigned)

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_SIGNATURE_INVALID, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    @Test
    fun `an imported manifest signed by an unknown key is rejected, LKG unchanged`() {
        val repo = repository(newStore())
        assertTrue(importer(repo).import(sign(manifest(version = 2))) is BootstrapBundleImportResult.Accepted)

        val unknownKeyCandidate = sign(manifest(version = 5, keyId = "totally-unknown-key"))
        val result = importer(repo).import(unknownKeyCandidate)

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_UNKNOWN_KEY, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    // --- 7 - previous-but-still-trusted rotated key accepted, no import-specific rotation ---

    @Test
    fun `an imported manifest signed by a previous-but-still-trusted rotated key is accepted`() {
        val repo = repository(newStore())
        assertTrue(importer(repo).import(sign(manifest(version = 2))) is BootstrapBundleImportResult.Accepted)

        val rotatedKeyCandidate = signWith(privRotated, manifest(version = 3, keyId = "key-2-rotated"))
        val result = importer(repo).import(rotatedKeyCandidate)

        assertTrue(result is BootstrapBundleImportResult.Accepted)
        assertEquals(3, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    // --- 9 - corrupt LKG does not introduce a second trust path ---

    @Test
    fun `a corrupt on-disk LKG does not prevent a valid import from following normal repository logic`() {
        val dir = tempFolder.newFolder()
        java.io.File(dir, "endpoint_manifest_lkg.bin").writeBytes(byteArrayOf(9, 9, 9))
        val store = FileLastKnownGoodManifestStore(dir) // corrupt file treated as absent, per B43 semantics
        val repo = repository(store) // falls back to embedded bootstrap (version 1)

        val result = importer(repo).import(sign(manifest(version = 2)))

        assertTrue(result is BootstrapBundleImportResult.Accepted)
        assertEquals(2, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }

    // --- 10 - atomicity: every rejection path leaves LKG bytes/object exactly as before ---

    @Test
    fun `every rejected import leaves the on-disk LKG bytes byte-for-byte unchanged`() {
        val dir = tempFolder.newFolder()
        val repo = repository(FileLastKnownGoodManifestStore(dir))
        assertTrue(importer(repo).import(sign(manifest(version = 2))) is BootstrapBundleImportResult.Accepted)

        val lkgFile = java.io.File(dir, "endpoint_manifest_lkg.bin")
        val bytesBefore = lkgFile.readBytes()

        val otherPriv = Ed25519PrivateKeyParameters(random)
        listOf(
            sign(manifest(version = 2)), // same version
            sign(manifest(version = 1)), // older
            signWith(otherPriv, manifest(version = 9)), // bad signature
            sign(manifest(version = 9, issuedAt = 1_000L, expiresAt = 1_500L)), // expired relative to now=2_000L
            sign(manifest(version = 9, keyId = "unknown-key")),
        ).forEach { candidate ->
            val result = importer(repo).import(candidate)
            assertTrue("expected rejection for $candidate, got $result", result is BootstrapBundleImportResult.Rejected)
        }

        assertTrue(java.util.Arrays.equals(bytesBefore, lkgFile.readBytes()))
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    // --- 14 - activation authority must never cross-trust a manifest ---

    @Test
    fun `a manifest signed only by an activation-issuer test key is rejected - activation authority never authorizes network facts`() {
        val activationPriv = Ed25519PrivateKeyParameters(random)
        val activationPub = activationPriv.generatePublicKey().encoded
        val activationAnchors = FixedActivationIssuerTrustAnchors(
            mapOf(ActivationIssuerKeyId("activation-issuer-test-key") to activationPub),
        )
        // The activation-issuer key genuinely IS trusted - but only by the activation authority, a disjoint type.
        assertTrue(activationAnchors.publicKeyFor(ActivationIssuerKeyId("activation-issuer-test-key")) != null)
        // The SAME key id carries no weight whatsoever with the manifest trust anchors used by this repository.
        assertNull(anchors.publicKeyFor(TrustedKeyId("activation-issuer-test-key")))

        val repo = repository(newStore())
        val activationSignedManifest = signWith(activationPriv, manifest(version = 2, keyId = "activation-issuer-test-key"))

        val result = importer(repo).import(activationSignedManifest)

        assertTrue(result is BootstrapBundleImportResult.Rejected)
        assertEquals(BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_UNKNOWN_KEY, (result as BootstrapBundleImportResult.Rejected).kind)
        assertEquals(1, repo.trusted()!!.manifestVersion) // still the embedded bootstrap - nothing adopted
    }

    // --- 15 - structural: no raw network-fact parameters exist on the import API ---

    @Test
    fun `the import API accepts only a SignedManifest - no raw host, IP, URL or port parameter exists`() {
        val importMethod = SignedBootstrapBundleImporter::class.java.methods.single { it.name == "import" }
        assertEquals(1, importMethod.parameterTypes.size)
        assertEquals(SignedManifest::class.java, importMethod.parameterTypes[0])
    }

    // --- 16/17 - malformed / trailing-byte encoded input fails closed before offer() ---

    @Test
    fun `importEncoded rejects malformed bytes as Malformed without touching the repository`() {
        val repo = repository(newStore())
        val result = importer(repo).importEncoded(byteArrayOf(1, 2, 3))

        assertTrue(result is BootstrapBundleImportResult.Malformed)
        assertEquals(1, repo.trusted()!!.manifestVersion) // unchanged - embedded bootstrap
    }

    @Test
    fun `importEncoded rejects trailing bytes appended after a valid container as Malformed`() {
        val repo = repository(newStore())
        val encoded = SignedManifestCodec.encode(sign(manifest(version = 2)))
        val withTrailingByte = encoded + byteArrayOf(0x7F)

        val result = importer(repo).importEncoded(withTrailingByte)

        assertTrue(result is BootstrapBundleImportResult.Malformed)
        assertEquals(1, repo.trusted()!!.manifestVersion) // never adopted
    }

    @Test
    fun `importEncoded accepts a validly encoded newer bundle via the exact SignedManifestCodec container`() {
        val repo = repository(newStore())
        val encoded = SignedManifestCodec.encode(sign(manifest(version = 2)))

        val result = importer(repo).importEncoded(encoded)

        assertTrue(result is BootstrapBundleImportResult.Accepted)
        assertEquals(2, repo.trusted()!!.manifestVersion)
    }

    // --- 18 - existing HTTPS-style offer() behavior is identical whether the importer exists or not ---

    @Test
    fun `offer() called directly (simulating the existing HTTPS path) behaves identically alongside the importer`() {
        val repo = repository(newStore())
        val direct = repo.offer(sign(manifest(version = 2)))
        assertTrue(direct is ManifestUpdateResult.Accepted)

        val imported = importer(repo).import(sign(manifest(version = 3)))
        assertTrue(imported is BootstrapBundleImportResult.Accepted)

        assertEquals(3, repo.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, repo.trustedSource())
    }
}
