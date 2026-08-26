package net.pocvpn.client.identity

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.amnezia.awg.crypto.Key
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class AwgClientKeyRepositoryTest {

    private fun newRepo(dir: java.io.File = Files.createTempDirectory("identity-test").toFile(), encryptor: AesGcmKeyEncryptor = FakeAesGcmKeyEncryptor()) =
        AwgClientKeyRepository(FileIdentityStore(dir), encryptor) to dir

    @Test
    fun `first call creates an identity`() = runBlocking {
        val (repo, _) = newRepo()
        val identity = repo.getOrCreateIdentity()
        assertTrue(identity.publicKeyBase64.isNotBlank())
    }

    @Test
    fun `second call returns the same identity`() = runBlocking {
        val (repo, _) = newRepo()
        val first = repo.getOrCreateIdentity()
        val second = repo.getOrCreateIdentity()
        assertEquals(first.publicKeyBase64, second.publicKeyBase64)
    }

    @Test
    fun `public key corresponds to the private key`() = runBlocking {
        val (repo, _) = newRepo()
        val identity = repo.getOrCreateIdentity()
        val privateKeyBase64 = repo.getPrivateKeyForTunnel()

        val derived = KeyPair(Key.fromBase64(privateKeyBase64))
        assertEquals(identity.publicKeyBase64, derived.getPublicKey().toBase64())
    }

    @Test
    fun `plaintext private key is not persisted on disk`() = runBlocking {
        val (repo, dir) = newRepo()
        repo.getOrCreateIdentity()
        val privateKeyBase64 = repo.getPrivateKeyForTunnel()

        val rawFileBytes = java.io.File(dir, "client_identity.bin").readBytes()
        val rawFileText = String(rawFileBytes, Charsets.ISO_8859_1)
        assertFalse(
            "identity file must not contain the plaintext private key",
            rawFileText.contains(privateKeyBase64),
        )
    }

    @Test
    fun `corrupted identity file fails closed instead of regenerating`(): Unit = runBlocking {
        val (repo, dir) = newRepo()
        repo.getOrCreateIdentity()
        // Truncate the persisted file to simulate storage corruption.
        val file = java.io.File(dir, "client_identity.bin")
        file.writeBytes(file.readBytes().copyOf(3))

        assertThrows(IdentityCorruptedException::class.java) {
            runBlocking { repo.getOrCreateIdentity() }
        }
    }

    @Test
    fun `decryption failure surfaces distinctly and does not regenerate silently`(): Unit = runBlocking {
        val dir = Files.createTempDirectory("identity-test").toFile()
        val (repoA, _) = newRepo(dir, FakeAesGcmKeyEncryptor(seed = 1L))
        repoA.getOrCreateIdentity()

        // Simulate a Keystore key that can no longer decrypt this ciphertext
        // (e.g. app data restored to a different device/Keystore).
        val (repoB, _) = newRepo(dir, FakeAesGcmKeyEncryptor(seed = 2L))
        assertThrows(IdentityDecryptionFailedException::class.java) {
            runBlocking { repoB.getPrivateKeyForTunnel() }
        }
    }

    @Test
    fun `concurrent getOrCreateIdentity calls converge on one identity`() = runBlocking {
        val (repo, _) = newRepo()
        val results = (1..20).map { async { repo.getOrCreateIdentity() } }.awaitAll()
        val distinctKeys = results.map { it.publicKeyBase64 }.toSet()
        assertEquals("all concurrent callers must observe the same identity", 1, distinctKeys.size)
    }

    @Test
    fun `clearIdentity removes the stored identity so a new one is generated next time`() = runBlocking {
        val (repo, _) = newRepo()
        val first = repo.getOrCreateIdentity()
        repo.clearIdentity()
        val second = repo.getOrCreateIdentity()
        assertNotEquals(first.publicKeyBase64, second.publicKeyBase64)
    }
}
