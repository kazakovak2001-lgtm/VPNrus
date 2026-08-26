package net.pocvpn.client.identity

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/**
 * Exercises the real AndroidKeyStore-backed encryptor on-device. This is
 * exactly the part FakeAesGcmKeyEncryptor (JVM unit tests) cannot cover:
 * an actual AndroidKeyStore AES key, generated on-device, non-exportable.
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreAesGcmEncryptorInstrumentedTest {

    private val alias = "net.pocvpn.client.test.identity.aesgcm"

    private fun cleanAlias() {
        KeyStore.getInstance("AndroidKeyStore").apply {
            load(null)
            if (containsAlias(alias)) deleteEntry(alias)
        }
    }

    @Test
    fun encryptThenDecrypt_roundTripsThroughRealAndroidKeystore() {
        cleanAlias()
        val encryptor = AndroidKeystoreAesGcmEncryptor(alias)
        val plaintext = "test-private-key-material-not-real".toByteArray()

        val payload = encryptor.encrypt(plaintext)
        val decrypted = encryptor.decrypt(payload)

        assertArrayEquals(plaintext, decrypted)
        cleanAlias()
    }

    @Test
    fun keyIsRegisteredInAndroidKeystore_underGivenAlias() {
        cleanAlias()
        val encryptor = AndroidKeystoreAesGcmEncryptor(alias)
        encryptor.encrypt("trigger-key-generation".toByteArray())

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "key must be generated under AndroidKeyStore, confirming it is device-Keystore-backed",
            !keyStore.containsAlias(alias),
        )
        cleanAlias()
    }

    @Test
    fun tamperedCiphertext_failsClosedWithIdentityDecryptionFailedException() {
        cleanAlias()
        val encryptor = AndroidKeystoreAesGcmEncryptor(alias)
        val payload = encryptor.encrypt("some-key-material".toByteArray())
        val tampered = payload.copy(ciphertext = payload.ciphertext.also { it[0] = it[0].inc() })

        assertThrows(IdentityDecryptionFailedException::class.java) {
            encryptor.decrypt(tampered)
        }
        cleanAlias()
    }

    @Test
    fun decryptWithDifferentAlias_afterOriginalKeyDeleted_failsClosed() {
        cleanAlias()
        val originalEncryptor = AndroidKeystoreAesGcmEncryptor(alias)
        val payload = originalEncryptor.encrypt("some-key-material".toByteArray())

        // Simulate the original Keystore key becoming unavailable (deleted / device-bound key
        // lost after a restore onto different hardware) - the ciphertext is still on disk but
        // can no longer be decrypted, which must fail closed rather than silently regenerating.
        cleanAlias()
        val afterKeyLoss = AndroidKeystoreAesGcmEncryptor(alias) // generates a NEW key under the same alias

        assertThrows(IdentityDecryptionFailedException::class.java) {
            afterKeyLoss.decrypt(payload)
        }
        cleanAlias()
    }
}
