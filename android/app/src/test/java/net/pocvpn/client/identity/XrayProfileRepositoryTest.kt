package net.pocvpn.client.identity

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
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
        java.io.File(dir, "xray_profile.bin").writeBytes(byteArrayOf(0, 0, 0, 99))
        val repo = newRepo(dir)

        assertThrows(XrayProfileCorruptedException::class.java) {
            runBlocking { repo.getProfileOrNull() }
        }
    }
}
