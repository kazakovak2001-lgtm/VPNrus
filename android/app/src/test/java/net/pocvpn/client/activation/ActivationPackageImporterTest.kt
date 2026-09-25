package net.pocvpn.client.activation

import net.pocvpn.client.reachability.ManifestSource
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.SecureRandom
import java.util.Base64

/** B56-5 - NovaActivationPackage parsing + ActivationPackageImporter ordering/rejection matrix. */
class ActivationPackageImporterTest {
    @get:Rule val tmp = TemporaryFolder()
    private lateinit var f: ActivationPackageFixtures

    @Before fun setUp() {
        f = ActivationPackageFixtures(tmp.newFolder())
    }

    private fun import(text: String, guard: ActivationReplayGuard = InMemoryActivationReplayGuard(), now: Long = f.now) =
        f.importer(guard).import(ActivationPackageInput.Text(text), now)

    private fun rejected(result: ActivationPackageImportResult): ActivationPackageRejectionKind =
        (result as ActivationPackageImportResult.Rejected).kind

    private fun verified(result: ActivationPackageImportResult) = result as ActivationPackageImportResult.Verified

    private fun b64(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun rawPackage(
        tag: String = NovaActivationPackage.DOMAIN_TAG,
        version: Int = 1,
        envelope: ByteArray? = ActivationEnvelopeCodec.encode(f.signEnvelope(f.envelope())),
        bundle: ByteArray? = null,
        level2: ByteArray? = null,
        trailing: ByteArray = ByteArray(0),
    ): String {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            val t = tag.toByteArray(Charsets.UTF_8)
            d.writeInt(t.size); d.write(t)
            d.writeInt(version)
            d.writeInt(envelope?.size ?: 0); envelope?.let { d.write(it) }
            d.writeInt(bundle?.size ?: 0); bundle?.let { d.write(it) }
            d.writeInt(level2?.size ?: 0); level2?.let { d.write(it) }
            d.write(trailing)
        }
        return NovaActivationPackage.TEXT_PREFIX + b64(out.toByteArray())
    }

    // --- Envelope ---

    @Test fun `valid package without bundle verifies and exposes the credential only after verification`() {
        val result = verified(import(f.packageText()))
        assertEquals(f.credential, result.envelope.credential.value)
        assertEquals(BootstrapStagingStatus.NOT_INCLUDED, result.bootstrap)
        assertNull(result.stagedManifestVersion)
    }

    @Test fun `round trip encode-parse preserves the signed envelope and bundle bytes`() {
        val bundle = f.bundleBytes(2)
        val signed = f.signEnvelope(f.envelope())
        val parsed = ActivationPackageParser.parse(ActivationPackageInput.Text(ActivationPackageParser.encodeText(NovaActivationPackage(signed, bundle))))
        parsed as ActivationPackageParseResult.Success
        assertEquals(signed, parsed.pkg.signedEnvelope)
        assertArrayEquals(bundle, parsed.pkg.bootstrapBundle)
    }

    @Test fun `bytes input (file) and text input (QR, deep link, clipboard) parse identically`() {
        val pkg = NovaActivationPackage(f.signEnvelope(f.envelope()), null)
        val fromBytes = f.importer().import(ActivationPackageInput.Bytes(ActivationPackageParser.encode(pkg)), f.now)
        assertTrue(fromBytes is ActivationPackageImportResult.Verified)
    }

    @Test fun `signature by a different key under the trusted key id is SIGNATURE_INVALID`() {
        val wrong = Ed25519PrivateKeyParameters(SecureRandom())
        assertEquals(ActivationPackageRejectionKind.SIGNATURE_INVALID, rejected(import(f.packageText(key = wrong))))
    }

    @Test fun `unknown issuer key id is ISSUER_UNKNOWN`() {
        val env = f.envelope(keyId = ActivationIssuerKeyId("someone-else"))
        assertEquals(ActivationPackageRejectionKind.ISSUER_UNKNOWN, rejected(import(f.packageText(env))))
    }

    @Test fun `production trust anchors do not accept a test-key envelope`() {
        val importer = ActivationPackageImporter(
            ProductionActivationIssuerTrustAnchors.trustAnchors(),
            net.pocvpn.client.reachability.SignedBootstrapBundleImporter(f.repository),
            InMemoryActivationReplayGuard(),
        )
        val env = f.envelope(keyId = ActivationIssuerKeyId(ProductionActivationIssuerTrustAnchors.PRIMARY_KEY_ID))
        val result = importer.import(ActivationPackageInput.Text(f.packageText(env)), f.now)
        assertEquals(ActivationPackageRejectionKind.SIGNATURE_INVALID, rejected(result))
    }

    @Test fun `expired envelope is EXPIRED`() {
        val env = f.envelope(notBefore = f.now - 10_000L, expiresAt = f.now)
        assertEquals(ActivationPackageRejectionKind.EXPIRED, rejected(import(f.packageText(env))))
    }

    @Test fun `not-yet-valid envelope is NOT_YET_VALID`() {
        val env = f.envelope(notBefore = f.now + 3_600_000L, expiresAt = f.now + 7_200_000L, issuedAt = f.now)
        assertEquals(ActivationPackageRejectionKind.NOT_YET_VALID, rejected(import(f.packageText(env))))
    }

    @Test fun `issuedAt far in the future is CLOCK_UNCERTAIN`() {
        val env = f.envelope(notBefore = f.now, expiresAt = f.now + 90L * 86_400_000L, issuedAt = f.now + 30L * 86_400_000L)
        assertEquals(ActivationPackageRejectionKind.CLOCK_UNCERTAIN, rejected(import(f.packageText(env))))
    }

    @Test fun `tampered credential inside a validly framed package is SIGNATURE_INVALID`() {
        val signed = f.signEnvelope(f.envelope())
        val tampered = SignedActivationEnvelope(signed.envelope.copy(credential = ActivationCredential("Zbc_def-123GHIjklMNOpqrSTUvwxYZ0123456789ab")), signed.signature)
        val text = ActivationPackageParser.encodeText(NovaActivationPackage(tampered, null))
        assertEquals(ActivationPackageRejectionKind.SIGNATURE_INVALID, rejected(import(text)))
    }

    @Test fun `single flipped byte anywhere in the package never verifies`() {
        val bytes = ActivationPackageParser.encode(NovaActivationPackage(f.signEnvelope(f.envelope()), null))
        for (i in bytes.indices) {
            val mutated = bytes.copyOf().also { it[i] = (it[i].toInt() xor 0x01).toByte() }
            val result = f.importer().import(ActivationPackageInput.Bytes(mutated), f.now)
            assertTrue("byte $i must not verify", result is ActivationPackageImportResult.Rejected)
        }
    }

    @Test fun `malformed text and garbage are PACKAGE_MALFORMED`() {
        for (text in listOf("", "nova-activation:1:", "nova-activation:1:!!!", "nova-activation:1:AAAA", NovaActivationPackage.TEXT_PREFIX + "x".repeat(10))) {
            assertEquals(text, ActivationPackageRejectionKind.PACKAGE_MALFORMED, rejected(import(text)))
        }
    }

    @Test fun `a raw activation credential is not a package`() {
        assertFalse(ActivationPackageParser.looksLikePackageText(f.credential))
        assertEquals(ActivationPackageRejectionKind.PACKAGE_MALFORMED, rejected(import(f.credential)))
    }

    @Test fun `non-canonical base64 alias of a valid package is rejected`() {
        val text = f.packageText()
        val last = text.last()
        val alias = text.dropLast(1) + (if (last == 'A') 'B' else 'A')
        assertTrue(import(alias) is ActivationPackageImportResult.Rejected)
    }

    @Test fun `wrong domain tag is PACKAGE_MALFORMED`() {
        assertEquals(ActivationPackageRejectionKind.PACKAGE_MALFORMED, rejected(import(rawPackage(tag = "NOVA_ACTIVATION_PACKAGE_V2"))))
    }

    @Test fun `unsupported schema version is PACKAGE_VERSION_UNSUPPORTED`() {
        assertEquals(ActivationPackageRejectionKind.PACKAGE_VERSION_UNSUPPORTED, rejected(import(rawPackage(version = 2))))
    }

    @Test fun `missing envelope is PACKAGE_MALFORMED`() {
        assertEquals(ActivationPackageRejectionKind.PACKAGE_MALFORMED, rejected(import(rawPackage(envelope = null))))
    }

    @Test fun `trailing bytes are PACKAGE_MALFORMED`() {
        assertEquals(ActivationPackageRejectionKind.PACKAGE_MALFORMED, rejected(import(rawPackage(trailing = byteArrayOf(0)))))
    }

    @Test fun `non-empty Level-2 section is LEVEL2_NOT_SUPPORTED, never silently ignored`() {
        assertEquals(ActivationPackageRejectionKind.LEVEL2_NOT_SUPPORTED, rejected(import(rawPackage(level2 = byteArrayOf(1, 2, 3)))))
    }

    @Test fun `envelope with wrong canonical encoding inside the package is rejected before verification`() {
        val envBytes = ActivationEnvelopeCodec.encode(f.signEnvelope(f.envelope()))
        envBytes[3] = 9 // envelope codec format version
        assertEquals(ActivationPackageRejectionKind.PACKAGE_VERSION_UNSUPPORTED, rejected(import(rawPackage(envelope = envBytes))))
    }

    // --- Bootstrap bundle ---

    @Test fun `valid referenced bundle is staged through the existing repository and becomes LKG`() {
        val bundle = f.bundleBytes(2)
        val env = f.envelope(bundleRef = f.refFor(bundle, 2))
        val result = verified(import(f.packageText(env, bundle)))
        assertEquals(BootstrapStagingStatus.STAGED, result.bootstrap)
        assertEquals(2, result.stagedManifestVersion)
        assertEquals(2, f.repository.trusted()!!.manifestVersion)
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, f.repository.trustedSource())
    }

    @Test fun `unreferenced bundle is still independently verified and staged`() {
        val result = verified(import(f.packageText(f.envelope(), f.bundleBytes(3))))
        assertEquals(BootstrapStagingStatus.STAGED, result.bootstrap)
        assertEquals(3, f.repository.trusted()!!.manifestVersion)
    }

    @Test fun `bundle hash not matching bootstrapBundleRef is BOOTSTRAP_BUNDLE_MISMATCH and nothing is staged`() {
        val env = f.envelope(bundleRef = f.refFor(f.bundleBytes(2), 2))
        // Same manifest version, different content (a substituted bundle) -> different exact-byte hash.
        val other = net.pocvpn.client.reachability.SignedManifestCodec.encode(f.signManifest(f.manifest(2, expiresAt = f.now + 86_400_000L)))
        assertEquals(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_MISMATCH, rejected(import(f.packageText(env, other))))
        assertEquals(1, f.repository.trusted()!!.manifestVersion)
    }

    @Test fun `bundleRef version not matching the bundle is BOOTSTRAP_BUNDLE_MISMATCH`() {
        val bundle = f.bundleBytes(2)
        val env = f.envelope(bundleRef = f.refFor(bundle, 5))
        assertEquals(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_MISMATCH, rejected(import(f.packageText(env, bundle))))
    }

    @Test fun `valid envelope with a bundle signed by an untrusted key is BOOTSTRAP_BUNDLE_INVALID and never staged`() {
        val bundle = f.bundleBytes(2, key = Ed25519PrivateKeyParameters(SecureRandom()))
        assertEquals(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID, rejected(import(f.packageText(f.envelope(), bundle))))
        assertEquals(1, f.repository.trusted()!!.manifestVersion)
    }

    @Test fun `activation issuer key can never authorize network facts - bundle signed by it is rejected`() {
        val bundle = f.bundleBytes(2, key = f.issuerKey)
        val env = f.envelope(bundleRef = f.refFor(bundle, 2))
        assertEquals(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID, rejected(import(f.packageText(env, bundle))))
        assertEquals(1, f.repository.trusted()!!.manifestVersion)
    }

    @Test fun `garbage bundle bytes are BOOTSTRAP_BUNDLE_INVALID`() {
        assertEquals(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID, rejected(import(f.packageText(f.envelope(), byteArrayOf(1, 2, 3)))))
    }

    @Test fun `older bundle is not an error but rollback protection keeps the newer LKG`() {
        assertEquals(BootstrapStagingStatus.STAGED, verified(import(f.packageText(f.envelope(), f.bundleBytes(4)))).bootstrap)
        val result = verified(import(f.packageText(f.envelope(nonceSeed = 9), f.bundleBytes(2))))
        assertEquals(BootstrapStagingStatus.ALREADY_CURRENT_OR_NEWER, result.bootstrap)
        assertEquals(4, f.repository.trusted()!!.manifestVersion)
    }

    @Test fun `envelope referencing a bundle the package lacks reports REFERENCED_BUT_NOT_INCLUDED`() {
        val env = f.envelope(bundleRef = f.refFor(f.bundleBytes(2), 2))
        assertEquals(BootstrapStagingStatus.REFERENCED_BUT_NOT_INCLUDED, verified(import(f.packageText(env))).bootstrap)
    }

    @Test fun `an invalid envelope never stages its bundle`() {
        val bundle = f.bundleBytes(2)
        val env = f.envelope(notBefore = f.now - 10_000L, expiresAt = f.now)
        assertEquals(ActivationPackageRejectionKind.EXPIRED, rejected(import(f.packageText(env, bundle))))
        assertEquals(1, f.repository.trusted()!!.manifestVersion)
    }

    // --- Replay ---

    @Test fun `a redeemed envelope is ALREADY_REDEEMED on re-import, a different envelope is not`() {
        val guard = InMemoryActivationReplayGuard()
        val result = verified(import(f.packageText(), guard))
        f.importer(guard).markRedeemed(result.envelope, f.now)
        assertEquals(ActivationPackageRejectionKind.ALREADY_REDEEMED, rejected(import(f.packageText(), guard)))
        assertTrue(import(f.packageText(f.envelope(nonceSeed = 42)), guard) is ActivationPackageImportResult.Verified)
    }

    // --- Leakage ---

    @Test fun `no result, input, package or state string contains the credential`() {
        val text = f.packageText(f.envelope(), f.bundleBytes(2))
        val strings = listOf(
            import(text).toString(),
            ActivationPackageInput.Text(text).toString(),
            (ActivationPackageParser.parse(ActivationPackageInput.Text(text)) as ActivationPackageParseResult.Success).pkg.toString(),
            ActivationPackageUiState.Activating(BootstrapStagingStatus.STAGED).toString(),
        ) + ActivationPackageRejectionKind.entries.map { ActivationPackageUiState.Rejected(it).toString() }
        strings.forEach { s ->
            assertFalse(s, s.contains(f.credential))
            assertFalse(s, s.contains(text))
        }
    }
}
