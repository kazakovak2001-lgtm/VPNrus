package net.pocvpn.client.identity

/** IV and ciphertext (GCM tag included in ciphertext) for one encrypted blob. */
data class EncryptedPayload(val iv: ByteArray, val ciphertext: ByteArray)

/**
 * Abstraction over "encrypt/decrypt bytes with a key I never expose."
 * The real implementation (AndroidKeystoreAesGcmEncryptor) backs this with a
 * non-exportable AndroidKeyStore AES-256-GCM key. This interface exists so
 * repository/orchestration logic (idempotence, corruption handling,
 * concurrency) can be unit-tested on the JVM with a fake encryptor, without
 * needing a real AndroidKeyStore.
 */
interface AesGcmKeyEncryptor {
    fun encrypt(plaintext: ByteArray): EncryptedPayload

    /** @throws IdentityDecryptionFailedException on AEAD auth failure or unavailable key. */
    fun decrypt(payload: EncryptedPayload): ByteArray
}
