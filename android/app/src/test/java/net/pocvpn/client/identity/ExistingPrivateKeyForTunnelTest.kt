package net.pocvpn.client.identity

import kotlinx.coroutines.runBlocking
import org.amnezia.awg.crypto.Key
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class ExistingPrivateKeyForTunnelTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun repo(dir: File, seed: Long = 1L) = AwgClientKeyRepository(FileIdentityStore(dir), FakeAesGcmKeyEncryptor(seed = seed))
    private fun identityFile(dir: File) = File(dir, "client_identity.bin")

    @Test
    fun `existing valid identity returns its own private key`() = runBlocking {
        val dir = tempFolder.root
        val r = repo(dir)
        val publicKey = r.getOrCreateIdentity().publicKeyBase64

        val result = r.getExistingPrivateKeyForTunnel()

        assertTrue(result is ExistingPrivateKeyResult.Present)
        result as ExistingPrivateKeyResult.Present
        assertEquals(publicKey, result.publicKeyBase64)
        // The returned private key derives the persisted public key - compared without printing either.
        val derived = KeyPair(Key.fromBase64(result.privateKeyBase64)).publicKey.toBase64()
        assertTrue("private key must match the persisted public key", derived == publicKey)
        assertEquals(r.getPrivateKeyForTunnel() == result.privateKeyBase64, true)
    }

    @Test
    fun `missing identity is Missing and creates no file`() = runBlocking {
        val dir = tempFolder.root
        val result = repo(dir).getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Missing, result)
        assertFalse(identityFile(dir).exists())
        assertEquals(ManagedKeyPeek.Absent, repo(dir).peekPublicKey())
    }

    @Test
    fun `repeated missing reads stay non-creating`() = runBlocking {
        val dir = tempFolder.root
        val r = repo(dir)
        repeat(5) { assertEquals(ExistingPrivateKeyResult.Missing, r.getExistingPrivateKeyForTunnel()) }
        assertFalse(identityFile(dir).exists())
        assertTrue(dir.listFiles().isNullOrEmpty())
    }

    @Test
    fun `corrupted identity file is Unavailable and is not replaced`() = runBlocking {
        val dir = tempFolder.root
        identityFile(dir).writeBytes(byteArrayOf(0, 0, 0, 9)) // unsupported format version
        val before = identityFile(dir).readBytes()

        val result = repo(dir).getExistingPrivateKeyForTunnel()

        assertTrue(result is ExistingPrivateKeyResult.Unavailable)
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
    }

    @Test
    fun `decryption failure is Unavailable and the identity is not replaced`() = runBlocking {
        val dir = tempFolder.root
        val original = repo(dir, seed = 1L).getOrCreateIdentity().publicKeyBase64
        val before = identityFile(dir).readBytes()

        val result = repo(dir, seed = 2L).getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Unavailable("IdentityDecryptionFailedException"), result)
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
        assertEquals(ManagedKeyPeek.Present(original), repo(dir).peekPublicKey())
    }

    @Test
    fun `existing getPrivateKeyForTunnel still creates on a missing identity`() = runBlocking {
        // Current callers (managed AND private) keep today's behavior in step 1.
        val dir = tempFolder.root
        val r = repo(dir)
        r.getPrivateKeyForTunnel()
        assertTrue(identityFile(dir).exists())
        assertTrue(r.getExistingPrivateKeyForTunnel() is ExistingPrivateKeyResult.Present)
    }

    @Test
    fun `Present never exposes key material through toString`() = runBlocking {
        val dir = tempFolder.root
        val r = repo(dir)
        val publicKey = r.getOrCreateIdentity().publicKeyBase64
        val result = r.getExistingPrivateKeyForTunnel() as ExistingPrivateKeyResult.Present
        val text = result.toString()
        assertFalse(text.contains(result.privateKeyBase64))
        assertFalse(text.contains(publicKey))
    }

    @Test
    fun `interface default fails closed`() = runBlocking {
        val minimal = object : ClientKeyRepository {
            override suspend fun getOrCreateIdentity() = ClientIdentity(KeyPair().publicKey.toBase64())
            override suspend fun getPublicKey() = getOrCreateIdentity().publicKeyBase64
            override suspend fun getPrivateKeyForTunnel() = "unused"
            override suspend fun clearIdentity() = Unit
        }
        assertTrue(minimal.getExistingPrivateKeyForTunnel() is ExistingPrivateKeyResult.Unavailable)
        assertTrue(minimal.peekPublicKey() is ManagedKeyPeek.Unavailable)
    }

    // --- F1: key-pair consistency ---

    /**
     * Writes an identity whose ciphertext holds [privatePlaintext] and whose public field is [publicKey],
     * encrypted with the SAME encryptor instance the returned repository decrypts with (two
     * FakeAesGcmKeyEncryptor instances are not guaranteed to derive the same AES key).
     */
    private fun repoWithIdentity(dir: File, privatePlaintext: String, publicKey: String): AwgClientKeyRepository {
        val encryptor = FakeAesGcmKeyEncryptor()
        val encrypted = encryptor.encrypt(privatePlaintext.toByteArray(Charsets.UTF_8))
        FileIdentityStore(dir).write(PersistedIdentity(encrypted, publicKey))
        return AwgClientKeyRepository(FileIdentityStore(dir), encryptor)
    }

    @Test
    fun `valid matching pair written directly returns Present`() = runBlocking {
        val dir = tempFolder.root
        val pair = KeyPair()
        val r = repoWithIdentity(dir, pair.privateKey.toBase64(), pair.publicKey.toBase64())

        val result = r.getExistingPrivateKeyForTunnel()

        assertTrue(result is ExistingPrivateKeyResult.Present)
        assertEquals(pair.publicKey.toBase64(), (result as ExistingPrivateKeyResult.Present).publicKeyBase64)
    }

    @Test
    fun `stored public key not derived from the private key is Unavailable and file unchanged`() = runBlocking {
        val dir = tempFolder.root
        val r = repoWithIdentity(dir, KeyPair().privateKey.toBase64(), KeyPair().publicKey.toBase64())
        val before = identityFile(dir).readBytes()

        val result = r.getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Unavailable("key pair mismatch"), result)
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
    }

    @Test
    fun `malformed decrypted private key is Unavailable and file unchanged`() = runBlocking {
        val dir = tempFolder.root
        val r = repoWithIdentity(dir, "not-a-wireguard-key", KeyPair().publicKey.toBase64())
        val before = identityFile(dir).readBytes()

        val result = r.getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Unavailable("malformed key"), result)
        assertFalse(result.toString().contains("not-a-wireguard-key"))
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
    }

    @Test
    fun `malformed stored public key is Unavailable and file unchanged`() = runBlocking {
        val dir = tempFolder.root
        val r = repoWithIdentity(dir, KeyPair().privateKey.toBase64(), "garbage-public-key")
        val before = identityFile(dir).readBytes()

        assertEquals(ExistingPrivateKeyResult.Unavailable("malformed key"), r.getExistingPrivateKeyForTunnel())
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
    }

    // --- F2: runtime failures ---

    private class ThrowingEncryptor(private val delegate: AesGcmKeyEncryptor) : AesGcmKeyEncryptor by delegate {
        override fun decrypt(payload: EncryptedPayload): ByteArray =
            throw java.security.ProviderException("keystore exploded")
    }

    @Test
    fun `runtime exception from decrypt is Unavailable, identity unchanged, nothing created`() = runBlocking {
        val dir = tempFolder.root
        val original = repo(dir).getOrCreateIdentity().publicKeyBase64
        val before = identityFile(dir).readBytes()
        val throwing = AwgClientKeyRepository(FileIdentityStore(dir), ThrowingEncryptor(FakeAesGcmKeyEncryptor(seed = 1L)))

        val result = throwing.getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Unavailable("ProviderException"), result)
        assertFalse(result.toString().contains("keystore exploded"))
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
        assertEquals(ManagedKeyPeek.Present(original), throwing.peekPublicKey())
        assertEquals(listOf("client_identity.bin"), dir.listFiles()!!.map { it.name })
    }

    @Test
    fun `runtime exception on a missing identity still reports Missing and creates nothing`() = runBlocking {
        val dir = tempFolder.root
        val throwing = AwgClientKeyRepository(FileIdentityStore(dir), ThrowingEncryptor(FakeAesGcmKeyEncryptor()))
        assertEquals(ExistingPrivateKeyResult.Missing, throwing.getExistingPrivateKeyForTunnel())
        assertFalse(identityFile(dir).exists())
    }

    // --- R1: runtime failure while reading the identity file ---

    @Test
    fun `runtime exception from store read is Unavailable and storage is untouched`() = runBlocking {
        val dir = tempFolder.root
        val original = repo(dir).getOrCreateIdentity().publicKeyBase64
        val before = identityFile(dir).readBytes()
        val throwingStore = object : IdentityFileStore by FileIdentityStore(dir) {
            override fun read(): IdentityLoadResult = throw SecurityException("denied /data/secret/path")
        }
        val r = AwgClientKeyRepository(throwingStore, FakeAesGcmKeyEncryptor())

        val result = r.getExistingPrivateKeyForTunnel()

        assertEquals(ExistingPrivateKeyResult.Unavailable("SecurityException"), result)
        assertFalse(result.toString().contains("secret"))
        assertTrue(before.contentEquals(identityFile(dir).readBytes()))
        assertEquals(listOf("client_identity.bin"), dir.listFiles()!!.map { it.name })
        assertEquals(ManagedKeyPeek.Present(original), repo(dir).peekPublicKey())
    }

    @Test
    fun `runtime exception from store read on an empty folder creates nothing`() = runBlocking {
        val dir = tempFolder.root
        val throwingStore = object : IdentityFileStore by FileIdentityStore(dir) {
            override fun read(): IdentityLoadResult = throw SecurityException("denied")
        }
        assertEquals(
            ExistingPrivateKeyResult.Unavailable("SecurityException"),
            AwgClientKeyRepository(throwingStore, FakeAesGcmKeyEncryptor()).getExistingPrivateKeyForTunnel(),
        )
        assertTrue(dir.listFiles().isNullOrEmpty())
    }

    @Test
    fun `separate repositories over separate files stay isolated`() = runBlocking {
        // Mirrors the managed vs PRIVATE split (distinct files): reading one never touches the other.
        val managedDir = tempFolder.newFolder("managed")
        val privateDir = tempFolder.newFolder("private")
        val privatePublic = repo(privateDir).getOrCreateIdentity().publicKeyBase64

        assertEquals(ExistingPrivateKeyResult.Missing, repo(managedDir).getExistingPrivateKeyForTunnel())
        assertEquals(ManagedKeyPeek.Present(privatePublic), repo(privateDir).peekPublicKey())
        assertFalse(identityFile(managedDir).exists())
        assertNotEquals(identityFile(managedDir).absolutePath, identityFile(privateDir).absolutePath)
    }
}
