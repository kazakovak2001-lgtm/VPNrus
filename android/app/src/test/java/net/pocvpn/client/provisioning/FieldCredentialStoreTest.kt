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
 *
 * Cross-host review fix: the store is keyed by endpoint host (Germany's
 * gateway and the Stockholm ingress role are separate control planes with
 * separate credentials - see FieldCredentialStore.kt's own docs), so every
 * test below exercises that a credential for one host is never confused
 * with, nor overwritten by, a credential for a different host.
 */
class FieldCredentialStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun store(): FileFieldCredentialStore =
        FileFieldCredentialStore(tmp.newFolder("field-credentials-${System.nanoTime()}"), FakeAesGcmKeyEncryptor())

    @Test
    fun `fresh install has no stored credential for any host`() = runTest {
        val s = store()
        assertNull(s.getOrNull("152.70.43.1"))
        assertNull(s.getOrNull("16.170.208.231"))
    }

    @Test
    fun `save then getOrNull round-trips the exact credential for that host`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "super-secret-device-credential", issuedByEndpointHost = "152.70.43.1"))
        val loaded = s.getOrNull("152.70.43.1")
        assertEquals("super-secret-device-credential", loaded?.credential)
        assertEquals("152.70.43.1", loaded?.issuedByEndpointHost)
    }

    @Test
    fun `a credential saved for one host is never returned for a different host`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "germany-credential", issuedByEndpointHost = "152.70.43.1"))
        assertNull(s.getOrNull("16.170.208.231"))
    }

    @Test
    fun `credentials for two different hosts coexist independently`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "germany-credential", issuedByEndpointHost = "152.70.43.1"))
        s.save(FieldCredential(credential = "ingress-credential", issuedByEndpointHost = "16.170.208.231"))

        assertEquals("germany-credential", s.getOrNull("152.70.43.1")?.credential)
        assertEquals("ingress-credential", s.getOrNull("16.170.208.231")?.credential)
    }

    @Test
    fun `the raw credential never appears in the on-disk bytes`() = runTest {
        val directory = tmp.newFolder("field-credentials-plaintext-check")
        val s = FileFieldCredentialStore(directory, FakeAesGcmKeyEncryptor())
        val secret = "this-must-never-appear-in-plaintext-on-disk"
        s.save(FieldCredential(credential = secret, issuedByEndpointHost = "152.70.43.1"))

        val files = directory.listFiles()!!
        assertTrue(files.isNotEmpty())
        for (file in files) {
            val onDiskAsLatin1 = String(file.readBytes(), Charsets.ISO_8859_1)
            assertFalse(onDiskAsLatin1.contains(secret))
        }
    }

    @Test
    fun `clear removes only the stored credential for that host`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "germany-credential", issuedByEndpointHost = "152.70.43.1"))
        s.save(FieldCredential(credential = "ingress-credential", issuedByEndpointHost = "16.170.208.231"))

        s.clear("152.70.43.1")

        assertNull(s.getOrNull("152.70.43.1"))
        assertEquals("ingress-credential", s.getOrNull("16.170.208.231")?.credential)
    }

    @Test
    fun `save overwrites a previously stored credential for the SAME host`() = runTest {
        val s = store()
        s.save(FieldCredential(credential = "first", issuedByEndpointHost = "152.70.43.1"))
        s.save(FieldCredential(credential = "second", issuedByEndpointHost = "152.70.43.1"))
        assertEquals("second", s.getOrNull("152.70.43.1")?.credential)
    }

    @Test
    fun `a truncated file fails closed with a corruption exception rather than a wrong value`() {
        val directory = tmp.newFolder("field-credentials-corrupt")
        val s = FileFieldCredentialStore(directory, FakeAesGcmKeyEncryptor())
        var threw = false
        runTest {
            s.save(FieldCredential("placeholder", "152.70.43.1"))
        }
        val files = directory.listFiles()!!
        files.first().writeBytes(byteArrayOf(0, 0, 0, 1))
        runTest {
            try {
                s.getOrNull("152.70.43.1")
            } catch (e: FieldCredentialCorruptedException) {
                threw = true
            }
        }
        assertTrue(threw)
    }

    @Test
    fun `InMemoryFieldCredentialStore is also keyed by endpoint host`() = runTest {
        val s = InMemoryFieldCredentialStore()
        assertNull(s.getOrNull("152.70.43.1"))
        s.save(FieldCredential("germany-c", "152.70.43.1"))
        s.save(FieldCredential("ingress-c", "16.170.208.231"))
        assertEquals("germany-c", s.getOrNull("152.70.43.1")?.credential)
        assertEquals("ingress-c", s.getOrNull("16.170.208.231")?.credential)
        s.clear("152.70.43.1")
        assertNull(s.getOrNull("152.70.43.1"))
        assertEquals("ingress-c", s.getOrNull("16.170.208.231")?.credential)
    }
}
