package net.pocvpn.client.identity

/**
 * Base type for identity-storage failures. Messages must never contain key
 * material - only structural/diagnostic reasons - since they may reach logs.
 */
sealed class IdentityStorageException(message: String) : Exception(message)

/**
 * The persisted identity file exists but is structurally invalid (truncated,
 * bad length header, etc). This is distinct from "no identity yet" and must
 * NOT be silently treated as first run - the caller must explicitly decide
 * whether to call clearIdentity() and regenerate.
 */
class IdentityCorruptedException(reason: String) : IdentityStorageException("identity storage corrupted: $reason")

/**
 * The persisted ciphertext is structurally valid but could not be decrypted -
 * most commonly because the AndroidKeyStore key that encrypted it is gone
 * (e.g. app data restored onto a different device/Keystore, or the Keystore
 * key was deleted). Device-bound Keystore keys make this unrecoverable by
 * design; the only path forward is an explicit clearIdentity() + regenerate.
 */
class IdentityDecryptionFailedException(reason: String) : IdentityStorageException("identity decryption failed: $reason")
