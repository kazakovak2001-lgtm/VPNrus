package net.pocvpn.client.identity

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.amnezia.awg.crypto.KeyPair
import java.nio.charset.StandardCharsets

/**
 * Owns the client's AmneziaWG keypair: generates it once via the upstream
 * KeyPair implementation, persists only the AES-GCM-encrypted private key,
 * and never returns the private key except to the transport layer that
 * needs it to build a tunnel config.
 */
interface ClientKeyRepository {
    /** Returns the existing identity, or generates+persists one on first call. Safe for concurrent callers. */
    suspend fun getOrCreateIdentity(): ClientIdentity

    /** Convenience accessor; equivalent to getOrCreateIdentity().publicKeyBase64. */
    suspend fun getPublicKey(): String

    /**
     * Decrypts and returns the private key for immediate use building a
     * tunnel config. Callers must not log, persist, or retain this value
     * beyond the call that consumes it.
     */
    suspend fun getPrivateKeyForTunnel(): String

    /** Deletes the persisted identity. The next getOrCreateIdentity() call generates a new one. */
    suspend fun clearIdentity()
}

class AwgClientKeyRepository(
    private val store: IdentityFileStore,
    private val encryptor: AesGcmKeyEncryptor,
) : ClientKeyRepository {

    private val mutex = Mutex()

    override suspend fun getOrCreateIdentity(): ClientIdentity = mutex.withLock {
        when (val result = store.read()) {
            is IdentityLoadResult.Found -> ClientIdentity(result.identity.publicKeyBase64)
            is IdentityLoadResult.NotFound -> generateAndPersist().let { ClientIdentity(it.publicKeyBase64) }
            is IdentityLoadResult.Corrupted -> throw IdentityCorruptedException(result.reason)
        }
    }

    override suspend fun getPublicKey(): String = getOrCreateIdentity().publicKeyBase64

    override suspend fun getPrivateKeyForTunnel(): String = mutex.withLock {
        val persisted = when (val result = store.read()) {
            is IdentityLoadResult.Found -> result.identity
            is IdentityLoadResult.NotFound -> generateAndPersist()
            is IdentityLoadResult.Corrupted -> throw IdentityCorruptedException(result.reason)
        }
        // decrypt() itself throws IdentityDecryptionFailedException on AEAD/Keystore failure - propagated as-is.
        val plaintext = encryptor.decrypt(persisted.encryptedPrivateKey)
        String(plaintext, StandardCharsets.UTF_8)
    }

    override suspend fun clearIdentity() = mutex.withLock {
        store.delete()
    }

    /** Caller must hold the mutex. */
    private fun generateAndPersist(): PersistedIdentity {
        val keyPair = KeyPair()
        val privateKeyBytes = keyPair.getPrivateKey().toBase64().toByteArray(StandardCharsets.UTF_8)
        val encrypted = encryptor.encrypt(privateKeyBytes)
        val persisted = PersistedIdentity(encrypted, keyPair.getPublicKey().toBase64())
        store.write(persisted)
        return persisted
    }
}
