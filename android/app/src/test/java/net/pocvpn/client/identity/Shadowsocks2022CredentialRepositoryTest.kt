package net.pocvpn.client.identity

import java.nio.file.Files
import java.util.Base64
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class Shadowsocks2022CredentialRepositoryTest {

    private val method = "2022-blake3-aes-256-gcm"
    private fun fakeKey(seed: Byte = 0) = Base64.getEncoder().encodeToString(ByteArray(32) { (it + seed).toByte() })

    private fun credential(endpointId: EndpointId, keyBase64: String = fakeKey()) =
        (Shadowsocks2022CredentialValidator.validate(endpointId, method, keyBase64) as Shadowsocks2022CredentialValidationResult.Valid).credential

    private fun newRepo(
        endpointId: EndpointId,
        dir: java.io.File = Files.createTempDirectory("ss2022-cred-test").toFile(),
        encryptor: AesGcmKeyEncryptor = FakeAesGcmKeyEncryptor(),
    ) = SecureShadowsocks2022CredentialRepository(endpointId, FileShadowsocks2022CredentialStore(dir, endpointId), encryptor)

    @Test
    fun `no stored credential returns Absent - never a fabricated one`() = runBlocking {
        val repo = newRepo(EndpointId("edge-a"))
        assertEquals(Shadowsocks2022CredentialGetResult.Absent, repo.getCredential())
    }

    @Test
    fun `a valid 32-byte fake credential stores and reads back for the same endpoint`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val cred = credential(endpointId)

        repo.storeCredential(cred)

        val result = repo.getCredential()
        assertTrue(result is Shadowsocks2022CredentialGetResult.Present)
        assertEquals(cred, (result as Shadowsocks2022CredentialGetResult.Present).credential)
    }

    @Test
    fun `endpoint A cannot read endpoint B credential - separate scoped files`() = runBlocking {
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointA = EndpointId("edge-a")
        val endpointB = EndpointId("edge-b")

        val repoA = newRepo(endpointA, dir)
        repoA.storeCredential(credential(endpointA, fakeKey(1)))

        val repoB = newRepo(endpointB, dir)
        assertEquals(Shadowsocks2022CredentialGetResult.Absent, repoB.getCredential())
    }

    @Test
    fun `rotation replaces the old credential atomically`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val original = credential(endpointId, fakeKey(1))
        val rotated = credential(endpointId, fakeKey(2))

        repo.storeCredential(original)
        repo.storeCredential(rotated)

        val result = repo.getCredential() as Shadowsocks2022CredentialGetResult.Present
        assertEquals(rotated, result.credential)
        assertFalse(result.credential == original)
    }

    @Test
    fun `deletion (revocation) removes the credential`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        repo.storeCredential(credential(endpointId))

        repo.deleteCredential()

        assertEquals(Shadowsocks2022CredentialGetResult.Absent, repo.getCredential())
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
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointId = EndpointId("edge-a")

        val repoA = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 1L))
        repoA.storeCredential(credential(endpointId))

        val repoB = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 2L))
        val result = repoB.getCredential()
        assertTrue("expected Corrupted, got $result", result is Shadowsocks2022CredentialGetResult.Corrupted)
    }

    @Test
    fun `a structurally corrupt stored file fails closed as Corrupted, never Absent`() = runBlocking {
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        dir.mkdirs()
        val endpointId = EndpointId("edge-a")
        // The real endpoint-scoped file name, computed the same way production does.
        java.io.File(dir, "shadowsocks2022_credential_${sanitizeForFileName(endpointId)}.bin").writeBytes(byteArrayOf(0, 0, 0, 99))

        val repo = newRepo(endpointId, dir)
        val result = repo.getCredential()
        assertTrue("expected Corrupted, got $result", result is Shadowsocks2022CredentialGetResult.Corrupted)
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
    fun `no fallback or default credential exists across distinct endpoints`() = runBlocking {
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointA = EndpointId("edge-a")
        val endpointB = EndpointId("edge-b")
        newRepo(endpointA, dir).storeCredential(credential(endpointA))

        // A brand new endpoint with no credential of its own must never see endpoint A's.
        assertEquals(Shadowsocks2022CredentialGetResult.Absent, newRepo(endpointB, dir).getCredential())
    }

    @Test
    fun `first write succeeds and is immediately readable`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val cred = credential(endpointId)

        repo.storeCredential(cred)

        assertEquals(Shadowsocks2022CredentialGetResult.Present(cred), repo.getCredential())
    }

    @Test
    fun `after a successful rotation only the new value is readable - old value is gone`() = runBlocking {
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId)
        val original = credential(endpointId, fakeKey(1))
        val rotated = credential(endpointId, fakeKey(2))

        repo.storeCredential(original)
        repo.storeCredential(rotated)

        val present = repo.getCredential() as Shadowsocks2022CredentialGetResult.Present
        assertEquals(rotated, present.credential)
        assertFalse(present.credential.key.base64 == original.key.base64)
    }

    @Test
    fun `no tmp file remains on disk after a successful write - Files-move consumes it, nothing left behind`() = runBlocking {
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val repo = newRepo(endpointId, dir)

        repo.storeCredential(credential(endpointId))

        val tmpFiles = dir.listFiles { f -> f.name.endsWith(".tmp") } ?: emptyArray()
        assertTrue("expected no leftover .tmp files, found: ${tmpFiles.toList()}", tmpFiles.isEmpty())
    }

    @Test
    fun `a failed replacement does not delete the old credential first - old credential survives the failure`() = runBlocking {
        // Deterministic, non-invasive way to force Files.move's ATOMIC_MOVE+REPLACE_EXISTING to fail
        // without inventing a fault-injection filesystem abstraction: hold an exclusive lock on the
        // destination file (a real, practical failure mode - e.g. another process/AV scanner has it
        // open) so the move cannot complete. The old file's bytes must still be intact and correct
        // afterward - proving this store never deletes-then-tries-to-replace (the exact anti-pattern
        // this Files.move-based implementation replaced).
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val encryptor = FakeAesGcmKeyEncryptor()
        val store = FileShadowsocks2022CredentialStore(dir, endpointId)
        val repo = SecureShadowsocks2022CredentialRepository(endpointId, store, encryptor)
        val original = credential(endpointId, fakeKey(1))
        val attemptedRotation = credential(endpointId, fakeKey(2))

        repo.storeCredential(original)
        val destinationFile = java.io.File(dir, "shadowsocks2022_credential_${sanitizeForFileName(endpointId)}.bin")
        assertTrue(destinationFile.exists())

        val lockedChannel = java.io.RandomAccessFile(destinationFile, "rw").channel
        val lock = try {
            lockedChannel.tryLock()
        } catch (_: java.io.IOException) {
            null
        }
        try {
            if (lock == null) {
                // This platform/filesystem doesn't support exclusive locks the way this test
                // expects - skip rather than assert a false failure unrelated to the store's own logic.
                return@runBlocking
            }
            org.junit.Assert.assertThrows(java.io.IOException::class.java) {
                runBlocking { repo.storeCredential(attemptedRotation) }
            }
        } finally {
            lock?.release()
            lockedChannel.close()
        }

        // The old credential must still be exactly what it was - never deleted, never corrupted.
        val afterFailedAttempt = repo.getCredential()
        assertEquals(Shadowsocks2022CredentialGetResult.Present(original), afterFailedAttempt)

        // No leftover .tmp file from the failed attempt either.
        val tmpFiles = dir.listFiles { f -> f.name.endsWith(".tmp") } ?: emptyArray()
        assertTrue("expected no leftover .tmp files after a failed write, found: ${tmpFiles.toList()}", tmpFiles.isEmpty())
    }

    @Test
    fun `no real secret value appears in a Corrupted result's reason string`() = runBlocking {
        val dir = Files.createTempDirectory("ss2022-cred-test").toFile()
        val endpointId = EndpointId("edge-a")
        val secret = fakeKey(7)

        val repoA = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 1L))
        repoA.storeCredential(credential(endpointId, secret))
        val repoB = newRepo(endpointId, dir, FakeAesGcmKeyEncryptor(seed = 2L))

        val result = repoB.getCredential() as Shadowsocks2022CredentialGetResult.Corrupted
        assertFalse(result.reason.contains(secret))
        assertFalse(result.toString().contains(secret))
    }
}
