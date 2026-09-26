package net.pocvpn.client.identity

import java.nio.file.Files
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mirrors [Shadowsocks2022CredentialRepositoryTest]'s own coverage exactly, adapted for Hysteria2's dual-secret (auth + optional obfuscation) shape. */
class Hysteria2CredentialRepositoryTest {

    private fun fakeSecret(seed: Byte = 0) = (0 until 64).joinToString("") { ((seed + it) and 0x0f).toString(16) }

    private fun credential(endpointId: EndpointId, authSecret: String = fakeSecret(), obfuscationSecret: String? = null) =
        (Hysteria2CredentialValidator.validate(endpointId, authSecret, obfuscationSecret) as Hysteria2CredentialValidationResult.Valid).credential

    private fun newRepo(
        endpointId: EndpointId,
        dir: java.io.File = Files.createTempDirectory("hy2-cred-test").toFile(),
        encryptor: AesGcmKeyEncryptor = FakeAesGcmKeyEncryptor(),
    ) = SecureHysteria2CredentialRepository(endpointId, FileHysteria2CredentialStore(dir, endpointId), encryptor)

    @Test
    fun `no stored credential returns Absent - never a fabricated one`() = runBlocking {
        val repo = newRepo(EndpointId("edge-a"))
        assertEquals(Hysteria2CredentialGetResult.Absent, repo.getCredential())
    }

    @Test
    fun `a valid credential stores and reads back for the same endpoint`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val cred = credential(endpointId)

        repo.storeCredential(cred)

        val result = repo.getCredential()
        assertTrue(result is Hysteria2CredentialGetResult.Present)
        assertEquals(cred, (result as Hysteria2CredentialGetResult.Present).credential)
    }

    @Test
    fun `a credential with an obfuscation secret round-trips both secrets`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val cred = credential(endpointId, obfuscationSecret = fakeSecret(9))

        repo.storeCredential(cred)

        val result = repo.getCredential() as Hysteria2CredentialGetResult.Present
        assertEquals(cred.authSecret, result.credential.authSecret)
        assertEquals(cred.obfuscationSecret, result.credential.obfuscationSecret)
    }

    @Test
    fun `endpoint A cannot read endpoint B credential - separate scoped files`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        val endpointA = EndpointId("edge-a")
        val endpointB = EndpointId("edge-b")

        val repoA = newRepo(endpointA, dir)
        repoA.storeCredential(credential(endpointA, fakeSecret(1)))

        val repoB = newRepo(endpointB, dir)
        assertEquals(Hysteria2CredentialGetResult.Absent, repoB.getCredential())
    }

    @Test
    fun `rotation replaces the old credential atomically`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val original = credential(endpointId, fakeSecret(1))
        val rotated = credential(endpointId, fakeSecret(2))

        repo.storeCredential(original)
        repo.storeCredential(rotated)

        val result = repo.getCredential() as Hysteria2CredentialGetResult.Present
        assertEquals(rotated, result.credential)
        assertFalse(result.credential == original)
    }

    @Test
    fun `deletion (revocation) removes the credential`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        repo.storeCredential(credential(endpointId))

        repo.deleteCredential()

        assertEquals(Hysteria2CredentialGetResult.Absent, repo.getCredential())
        assertFalse(repo.credentialExists())
    }

    @Test
    fun `credentialExists reflects presence without needing a successful decrypt`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        assertFalse(repo.credentialExists())

        repo.storeCredential(credential(endpointId))
        assertTrue(repo.credentialExists())
    }

    @Test
    fun `a credential encrypted with one Keystore key cannot be decrypted with another - fails closed as Corrupted`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        val endpointId = EndpointId("edge-a")

        val repoA = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 1L))
        repoA.storeCredential(credential(endpointId))

        val repoB = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 2L))
        val result = repoB.getCredential()
        assertTrue("expected Corrupted, got $result", result is Hysteria2CredentialGetResult.Corrupted)
    }

    @Test
    fun `a structurally corrupt stored file fails closed as Corrupted, never Absent`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        dir.mkdirs()
        val endpointId = EndpointId("edge-a")
        java.io.File(dir, "hysteria2_credential_${sanitizeForFileName(endpointId)}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))

        val repo = newRepo(endpointId, dir)
        val result = repo.getCredential()
        assertTrue("expected Corrupted, got $result", result is Hysteria2CredentialGetResult.Corrupted)
    }

    @Test
    fun `storing a credential for the wrong endpoint is refused, never silently written`() {
        val repoForA = newRepo(EndpointId("edge-a"))
        val credentialForB = credential(EndpointId("edge-b"))
        org.junit.Assert.assertThrows(IllegalArgumentException::class.java) {
            runBlocking { repoForA.storeCredential(credentialForB) }
        }
    }

    @Test
    fun `absent credential is distinct from corrupted credential`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId, dir)

        // Nothing written yet.
        assertEquals(Hysteria2CredentialGetResult.Absent, repo.getCredential())

        // Now corrupt it.
        dir.mkdirs()
        java.io.File(dir, "hysteria2_credential_${sanitizeForFileName(endpointId)}.bin").writeBytes(byteArrayOf(1, 2, 3))
        val corrupted = repo.getCredential()
        assertTrue(corrupted is Hysteria2CredentialGetResult.Corrupted)
        // Distinct sealed cases - never conflated.
        assertFalse(corrupted == Hysteria2CredentialGetResult.Absent)
    }

    @Test
    fun `no tmp file remains on disk after a successful write`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId, dir)

        repo.storeCredential(credential(endpointId))

        val tmpFiles = dir.listFiles { f -> f.name.endsWith(".tmp") } ?: emptyArray()
        assertTrue("expected no leftover .tmp files, found: ${tmpFiles.toList()}", tmpFiles.isEmpty())
    }

    @Test
    fun `no real secret value appears in a Corrupted result's reason string`() = runBlocking {
        val dir = Files.createTempDirectory("hy2-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val secret = fakeSecret(7)

        val repoA = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 1L))
        repoA.storeCredential(credential(endpointId, secret))
        val repoB = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 2L))

        val result = repoB.getCredential() as Hysteria2CredentialGetResult.Corrupted
        assertFalse(result.reason.contains(secret))
        assertFalse(result.toString().contains(secret))
    }
}
