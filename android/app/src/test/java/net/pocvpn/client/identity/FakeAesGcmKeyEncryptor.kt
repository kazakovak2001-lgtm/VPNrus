package net.pocvpn.client.identity

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * JVM test double for AesGcmKeyEncryptor. Uses a real in-memory AES-256-GCM
 * key (plain javax.crypto, not AndroidKeyStore) so repository orchestration
 * logic - idempotence, corruption handling, concurrency, decrypt-failure
 * handling - can be exercised with the exact same encrypt/decrypt/AEAD
 * contract as production, without a real Android Keystore. AndroidKeyStore-
 * specific guarantees (non-exportability, device binding) are NOT covered by
 * this fake - see the androidTest instrumented test for that.
 */
class FakeAesGcmKeyEncryptor(seed: Long = 1L) : AesGcmKeyEncryptor {
    private val key: SecretKey = KeyGenerator.getInstance("AES").apply {
        init(256, java.security.SecureRandom(seed.toString().toByteArray()))
    }.generateKey()

    override fun encrypt(plaintext: ByteArray): EncryptedPayload {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return EncryptedPayload(iv = cipher.iv, ciphertext = cipher.doFinal(plaintext))
    }

    override fun decrypt(payload: EncryptedPayload): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, payload.iv))
            return cipher.doFinal(payload.ciphertext)
        } catch (e: AEADBadTagException) {
            throw IdentityDecryptionFailedException("AEAD authentication failed (fake encryptor)")
        }
    }
}
