package net.pocvpn.client.identity

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.amnezia.awg.crypto.Key
import org.amnezia.awg.crypto.KeyFormatException
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

    /**
     * Phase A - reads the current public key WITHOUT ever generating one (unlike
     * [getOrCreateIdentity]). Defaults to Unavailable so an implementation that
     * cannot answer fails closed for AWG eligibility.
     */
    suspend fun peekPublicKey(): ManagedKeyPeek = ManagedKeyPeek.Unavailable("peek not supported")

    /**
     * Phase B step 1 - the private key of the EXISTING identity only. Unlike
     * [getPrivateKeyForTunnel] it never generates or replaces an identity: a
     * missing file is [ExistingPrivateKeyResult.Missing], a corrupted file or a
     * decryption failure is [ExistingPrivateKeyResult.Unavailable]. Defaults
     * to Unavailable so an implementation that cannot answer fails closed.
     */
    suspend fun getExistingPrivateKeyForTunnel(): ExistingPrivateKeyResult =
        ExistingPrivateKeyResult.Unavailable("existing-key read not supported")
}

sealed class ExistingPrivateKeyResult {
    /** [toString] is overridden so the key can never reach a log or test report. */
    class Present(val privateKeyBase64: String, val publicKeyBase64: String) : ExistingPrivateKeyResult() {
        override fun toString(): String = "Present(<redacted>)"
    }
    object Missing : ExistingPrivateKeyResult()
    data class Unavailable(val reason: String) : ExistingPrivateKeyResult()
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

    override suspend fun peekPublicKey(): ManagedKeyPeek = mutex.withLock {
        when (val result = store.read()) {
            is IdentityLoadResult.Found -> ManagedKeyPeek.Present(result.identity.publicKeyBase64)
            is IdentityLoadResult.NotFound -> ManagedKeyPeek.Absent
            is IdentityLoadResult.Corrupted -> ManagedKeyPeek.Unavailable(result.reason)
        }
    }

    override suspend fun getExistingPrivateKeyForTunnel(): ExistingPrivateKeyResult = mutex.withLock {
        // Non-suspending block: no CancellationException can originate here.
        // Reasons carry only exception class names, never key material. The
        // store read is inside the same boundary (R1): e.g. a SecurityException
        // from the file system is typed Unavailable, not an escaping exception.
        try {
            val persisted = when (val result = store.read()) {
                is IdentityLoadResult.Found -> result.identity
                is IdentityLoadResult.NotFound -> return@withLock ExistingPrivateKeyResult.Missing
                is IdentityLoadResult.Corrupted -> return@withLock ExistingPrivateKeyResult.Unavailable(result.reason)
            }
            val privateKeyBase64 = String(encryptor.decrypt(persisted.encryptedPrivateKey), StandardCharsets.UTF_8)
            // F1 - only a CONSISTENT pair is returned: the decrypted private key
            // must derive exactly the stored public key (same upstream primitives
            // AwgConfigMapper uses to build the tunnel).
            val derivedPublic = KeyPair(Key.fromBase64(privateKeyBase64)).publicKey
            if (derivedPublic != Key.fromBase64(persisted.publicKeyBase64)) {
                return@withLock ExistingPrivateKeyResult.Unavailable("key pair mismatch")
            }
            ExistingPrivateKeyResult.Present(privateKeyBase64, persisted.publicKeyBase64)
        } catch (e: IdentityStorageException) {
            ExistingPrivateKeyResult.Unavailable(e.javaClass.simpleName)
        } catch (e: KeyFormatException) {
            ExistingPrivateKeyResult.Unavailable("malformed key")
        } catch (e: RuntimeException) {
            // F2 - e.g. java.security.ProviderException from Android Keystore,
            // which AndroidKeystoreAesGcmEncryptor does not convert.
            ExistingPrivateKeyResult.Unavailable(e.javaClass.simpleName)
        }
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
