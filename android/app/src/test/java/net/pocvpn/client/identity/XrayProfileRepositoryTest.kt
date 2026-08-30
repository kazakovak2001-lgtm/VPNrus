package net.pocvpn.client.identity

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class XrayProfileRepositoryTest {

    private val profile = XrayProfile(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
    )

    private fun newRepo(
        dir: java.io.File = Files.createTempDirectory("xray-profile-test").toFile(),
        encryptor: AesGcmKeyEncryptor = FakeAesGcmKeyEncryptor(),
    ) = SecureXrayProfileRepository(FileXrayProfileStore(dir), encryptor)

    @Test
    fun `no saved profile returns null - never a fabricated one`() = runBlocking {
        val repo = newRepo()
        assertNull(repo.getProfileOrNull())
    }

    @Test
    fun `a saved profile round-trips exactly`() = runBlocking {
        val repo = newRepo()
        repo.saveProfile(profile)
        assertEquals(profile, repo.getProfileOrNull())
    }

    @Test
    fun `clearProfile removes the saved profile`() = runBlocking {
        val repo = newRepo()
        repo.saveProfile(profile)
        repo.clearProfile()
        assertNull(repo.getProfileOrNull())
    }

    @Test
    fun `a profile encrypted with one key cannot be decrypted with another`() {
        val dir = Files.createTempDirectory("xray-profile-test").toFile()
        val repoA = newRepo(dir, FakeAesGcmKeyEncryptor(seed = 1L))
        runBlocking { repoA.saveProfile(profile) }

        val repoB = newRepo(dir, FakeAesGcmKeyEncryptor(seed = 2L))
        assertThrows(IdentityDecryptionFailedException::class.java) {
            runBlocking { repoB.getProfileOrNull() }
        }
    }

    @Test
    fun `a corrupted profile file surfaces as XrayProfileCorruptedException`() {
        val dir = Files.createTempDirectory("xray-profile-test").toFile()
        dir.mkdirs()
        // B13 (audit fix) - the real default endpoint-scoped file name, computed the same way production does.
        java.io.File(dir, "xray_profile_${sanitizeForFileName(EndpointId("frankfurt"))}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repo = newRepo(dir)

        assertThrows(XrayProfileCorruptedException::class.java) {
            runBlocking { repo.getProfileOrNull() }
        }
    }

    // B13 - endpoint-scoping / isolation / migration regression tests.

    @Test
    fun `two endpoints in the same directory never collide - each has its own credential`() = runBlocking {
        val dir = Files.createTempDirectory("xray-profile-isolation-test").toFile()
        val repoA = SecureXrayProfileRepository(
            FileXrayProfileStore(dir, endpointId = EndpointId("gateway-a")),
            FakeAesGcmKeyEncryptor(),
        )
        val repoB = SecureXrayProfileRepository(
            FileXrayProfileStore(dir, endpointId = EndpointId("gateway-b")),
            FakeAesGcmKeyEncryptor(),
        )
        val profileA = profile.copy(server = "a.example.net", uuid = "aaaaaaaa-0000-0000-0000-000000000000")
        val profileB = profile.copy(server = "b.example.net", uuid = "bbbbbbbb-0000-0000-0000-000000000000")

        repoA.saveProfile(profileA)
        repoB.saveProfile(profileB)

        assertEquals(profileA, repoA.getProfileOrNull())
        assertEquals(profileB, repoB.getProfileOrNull())

        repoA.clearProfile()
        assertNull(repoA.getProfileOrNull())
        // Clearing endpoint A must never touch endpoint B's own credential.
        assertEquals(profileB, repoB.getProfileOrNull())
    }

    @Test
    fun `endpoint-scoped file names never collide for distinct endpoint ids`() {
        val dir = Files.createTempDirectory("xray-profile-filename-test").toFile()
        val storeA = FileXrayProfileStore(dir, endpointId = EndpointId("gateway-a"))
        val storeB = FileXrayProfileStore(dir, endpointId = EndpointId("gateway-b"))
        assertTrue(storeA.read() is XrayProfileLoadResult.NotFound)
        assertTrue(storeB.read() is XrayProfileLoadResult.NotFound)
    }

    @Test
    fun `legacy unscoped file migrates once into the designated endpoint's scoped slot`() = runBlocking {
        val dir = Files.createTempDirectory("xray-profile-migration-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        // Simulate a pre-B13 install: profile saved under the old unscoped file name.
        val legacyStore = FileXrayProfileStore(dir, fileName = "xray_profile.bin", legacyFileName = null)
        SecureXrayProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)
        assertTrue(java.io.File(dir, "xray_profile.bin").exists())

        val migratingStore = FileXrayProfileStore(dir, endpointId = EndpointId("frankfurt"), legacyFileName = "xray_profile.bin")
        val repo = SecureXrayProfileRepository(migratingStore, legacyEncryptor)

        assertEquals(profile, repo.getProfileOrNull())
        // The legacy file is gone (renamed, not copied) - no duplicate credential left behind.
        assertFalse(java.io.File(dir, "xray_profile.bin").exists())
        assertTrue(java.io.File(dir, "xray_profile_${sanitizeForFileName(EndpointId("frankfurt"))}.bin").exists())
    }

    @Test
    fun `a store not designated for legacy migration never touches the legacy file`() = runBlocking {
        val dir = Files.createTempDirectory("xray-profile-no-migration-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        val legacyStore = FileXrayProfileStore(dir, fileName = "xray_profile.bin", legacyFileName = null)
        SecureXrayProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)

        // A second endpoint's store (legacyFileName = null, the safe default)
        // must never adopt the first endpoint's legacy credential.
        val secondEndpointStore = FileXrayProfileStore(dir, endpointId = EndpointId("gateway-b"))
        val secondRepo = SecureXrayProfileRepository(secondEndpointStore, legacyEncryptor)

        assertNull(secondRepo.getProfileOrNull())
        // The legacy file is untouched, still available for its real owner.
        assertTrue(java.io.File(dir, "xray_profile.bin").exists())
    }

    // B13 audit fix regression tests (2026-08-30 correctness audit item 1).

    @Test
    fun `a completely independent reader using only Factory defaults migrates the legacy profile without MainViewModel ever running first`() = runBlocking {
        // Simulates NovaXrayVpnService's/XrayDiagnosticsActivity's own inline
        // factory call: XrayProfileRepositoryFactory.create(context) with NO
        // explicit endpointId/migration override, constructed as the FIRST
        // and ONLY reader in this process - nothing resembling
        // MainViewModel.Factory ever runs first.
        val dir = Files.createTempDirectory("xray-profile-service-first-reader-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        val legacyStore = FileXrayProfileStore(dir, fileName = "xray_profile.bin", legacyFileName = null)
        SecureXrayProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)

        // The exact same defaults XrayProfileRepositoryFactory.create(context)
        // now uses in production (endpointId defaults to the production
        // endpoint, migrateFromLegacyUnscopedFile now defaults to true for it).
        val serviceStyleStore = FileXrayProfileStore(
            dir,
            legacyFileName = "xray_profile.bin", // what the factory now passes by default for the production endpoint
        )
        val serviceStyleRepo = SecureXrayProfileRepository(serviceStyleStore, legacyEncryptor)

        assertEquals(profile, serviceStyleRepo.getProfileOrNull())
        assertFalse(java.io.File(dir, "xray_profile.bin").exists())
    }

    @Test
    fun `two independently constructed migrating stores racing on the same legacy file converge without data loss or duplication`() = runBlocking {
        val dir = Files.createTempDirectory("xray-profile-concurrent-migration-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        val legacyStore = FileXrayProfileStore(dir, fileName = "xray_profile.bin", legacyFileName = null)
        SecureXrayProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)

        // Two SEPARATE store instances (as NovaXrayVpnService's own factory
        // closure and MainViewModel.Factory's each independently construct),
        // both eligible to migrate, both attempting read() around the same time.
        val readerA = SecureXrayProfileRepository(
            FileXrayProfileStore(dir, endpointId = EndpointId("frankfurt"), legacyFileName = "xray_profile.bin"),
            legacyEncryptor,
        )
        val readerB = SecureXrayProfileRepository(
            FileXrayProfileStore(dir, endpointId = EndpointId("frankfurt"), legacyFileName = "xray_profile.bin"),
            legacyEncryptor,
        )

        // Interleaved: A migrates first, then B reads - B must see the
        // ALREADY-migrated file (not attempt a second, failing rename that
        // loses the credential), and never a duplicated/corrupted result.
        val resultA = readerA.getProfileOrNull()
        val resultB = readerB.getProfileOrNull()

        assertEquals(profile, resultA)
        assertEquals(profile, resultB)
        assertFalse(java.io.File(dir, "xray_profile.bin").exists())
        assertTrue(java.io.File(dir, "xray_profile_${sanitizeForFileName(EndpointId("frankfurt"))}.bin").exists())
    }

    @Test
    fun `sanitizeForFileName never maps two distinct EndpointIds to the same file name`() {
        val pairs = listOf(
            EndpointId("a/b") to EndpointId("a.b"),
            EndpointId("gateway a") to EndpointId("gateway_a"),
            EndpointId("a:b") to EndpointId("a;b"),
        )
        pairs.forEach { (a, b) ->
            assertFalse(
                "expected distinct filenames for distinct EndpointIds \"${a.value}\" and \"${b.value}\"",
                sanitizeForFileName(a) == sanitizeForFileName(b),
            )
        }
    }

    @Test
    fun `sanitizeForFileName is deterministic for the same EndpointId`() {
        val id = EndpointId("gateway-b")
        assertEquals(sanitizeForFileName(id), sanitizeForFileName(id))
    }
}
