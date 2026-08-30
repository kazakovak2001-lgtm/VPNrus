package net.pocvpn.client.identity

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/** B13 - the TLS/TCP counterpart of XrayProfileRepositoryTest's endpoint-scoping/isolation/migration coverage. */
class XrayTlsProfileRepositoryTest {

    private val profile = XrayTlsProfile(
        server = "tls.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
    )

    private fun newRepo(
        dir: java.io.File = Files.createTempDirectory("xray-tls-profile-test").toFile(),
        encryptor: AesGcmKeyEncryptor = FakeAesGcmKeyEncryptor(),
    ) = SecureXrayTlsProfileRepository(FileXrayTlsProfileStore(dir), encryptor)

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
    fun `two endpoints in the same directory never collide - each has its own credential`() = runBlocking {
        val dir = Files.createTempDirectory("xray-tls-profile-isolation-test").toFile()
        val repoA = SecureXrayTlsProfileRepository(
            FileXrayTlsProfileStore(dir, endpointId = EndpointId("gateway-a")),
            FakeAesGcmKeyEncryptor(),
        )
        val repoB = SecureXrayTlsProfileRepository(
            FileXrayTlsProfileStore(dir, endpointId = EndpointId("gateway-b")),
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
        assertEquals(profileB, repoB.getProfileOrNull())
    }

    @Test
    fun `legacy unscoped file migrates once into the designated endpoint's scoped slot`() = runBlocking {
        val dir = Files.createTempDirectory("xray-tls-profile-migration-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        val legacyStore = FileXrayTlsProfileStore(dir, fileName = "xray_tls_profile.bin", legacyFileName = null)
        SecureXrayTlsProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)
        assertTrue(java.io.File(dir, "xray_tls_profile.bin").exists())

        val migratingStore = FileXrayTlsProfileStore(dir, endpointId = EndpointId("frankfurt"), legacyFileName = "xray_tls_profile.bin")
        val repo = SecureXrayTlsProfileRepository(migratingStore, legacyEncryptor)

        assertEquals(profile, repo.getProfileOrNull())
        assertFalse(java.io.File(dir, "xray_tls_profile.bin").exists())
        assertTrue(java.io.File(dir, "xray_tls_profile_${sanitizeForFileName(EndpointId("frankfurt"))}.bin").exists())
    }

    @Test
    fun `a store not designated for legacy migration never touches the legacy file`() = runBlocking {
        val dir = Files.createTempDirectory("xray-tls-profile-no-migration-test").toFile()
        val legacyEncryptor = FakeAesGcmKeyEncryptor()
        val legacyStore = FileXrayTlsProfileStore(dir, fileName = "xray_tls_profile.bin", legacyFileName = null)
        SecureXrayTlsProfileRepository(legacyStore, legacyEncryptor).saveProfile(profile)

        val secondEndpointStore = FileXrayTlsProfileStore(dir, endpointId = EndpointId("gateway-b"))
        val secondRepo = SecureXrayTlsProfileRepository(secondEndpointStore, legacyEncryptor)

        assertNull(secondRepo.getProfileOrNull())
        assertTrue(java.io.File(dir, "xray_tls_profile.bin").exists())
    }
}
