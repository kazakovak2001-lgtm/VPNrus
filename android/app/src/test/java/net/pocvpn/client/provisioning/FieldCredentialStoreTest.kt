package net.pocvpn.client.provisioning

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Russia field-test zero-touch enrollment - [FileFieldCredentialStore]'s
 * own persistence/encryption contract. Same "fake in-memory AES-GCM
 * encryptor, real file I/O" split as [net.pocvpn.client.relay.FileIngressProfileStore]'s
 * own test suite - covers test requirements #10 ("credential is stored
 * encrypted/private on Android") and #11 ("credential never appears in
 * diagnostics/logs" - the raw-bytes-on-disk half of that).
 */
class FieldCredentialStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun store(): FileFieldCredentialStore =
        FileFieldCredentialStore(tmp.newFile("field-credential.bin").also { it.delete() }, FakeAesGcmKeyEncryptor())

    @Test
    fun `fresh install has no stored credential`() = runTest {
        assertNull(store().getOrNull())
    }

    @Test
    fun `save then getOrNull round-trips the exact credential and endpoint host`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "super-secret-device-credential", issuedByEndpointHost = "152.70.43.1"))
        val loaded = s.getOrNull()
        assertEquals("super-secret-device-credential", loaded?.credential)
        assertEquals("152.70.43.1", loaded?.issuedByEndpointHost)
    }

    @Test
    fun `the raw credential never appears in the on-disk bytes`() = runTest {
        val file = tmp.newFile("field-credential-2.bin").also { it.delete() }
        val s = FileFieldCredentialStore(file, FakeAesGcmKeyEncryptor())
        val secret = "this-must-never-appear-in-plaintext-on-disk"
        s.save(FieldCredential(credential = secret, issuedByEndpointHost = "152.70.43.1"))

        val onDisk = file.readBytes()
        val onDiskAsLatin1 = String(onDisk, Charsets.ISO_8859_1)
        assertFalse(onDiskAsLatin1.contains(secret))
    }

    @Test
    fun `clear removes the stored credential`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "x", issuedByEndpointHost = "152.70.43.1"))
        s.clear()
        assertNull(s.getOrNull())
    }

    @Test
    fun `save overwrites a previously stored credential`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "first", issuedByEndpointHost = "152.70.43.1"))
        s.save(FieldCredential(credential = "second", issuedByEndpointHost = "16.170.208.231"))
        val loaded = s.getOrNull()
        assertEquals("second", loaded?.credential)
        assertEquals("16.170.208.231", loaded?.issuedByEndpointHost)
    }

    @Test
    fun `a truncated file fails closed with a corruption exception rather than a wrong value`() {
        val file = tmp.newFile("field-credential-3.bin").also { it.delete() }
        file.writeBytes(byteArrayOf(0, 0, 0, 1))
        val s = FileFieldCredentialStore(file, FakeAesGcmKeyEncryptor())
        var threw = false
        runTest {
            try {
                s.getOrNull()
            } catch (e: FieldCredentialCorruptedException) {
                threw = true
            }
        }
        assertTrue(threw)
    }

    @Test
    fun `InMemoryFieldCredentialStore round-trips for tests without real file I-O`() = runTest {
        val s = InMemoryFieldCredentialStore()
        assertNull(s.getOrNull())
        s.save(FieldCredential("c", "h"))
        assertEquals("c", s.getOrNull()?.credential)
        s.clear()
        assertNull(s.getOrNull())
    }
}
