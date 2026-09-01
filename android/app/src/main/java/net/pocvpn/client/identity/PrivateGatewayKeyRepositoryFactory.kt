package net.pocvpn.client.identity

import android.content.Context

/**
 * B22 (architecture constraint 1) - "reuse the project's existing
 * device-local tunnel identity/key-storage architecture where possible":
 * this reuses [AwgClientKeyRepository]/[FileIdentityStore]/
 * [AndroidKeystoreAesGcmEncryptor] byte-for-byte unchanged (zero new
 * secret-storage code) - only the backing file name and AndroidKeyStore
 * alias differ from [ClientKeyRepositoryFactory], so the private gateway's
 * keypair is a genuinely DISTINCT identity from the managed-network one
 * (never the same keypair reused across a managed and a private gateway -
 * that would link the same device fingerprint across both, an unwanted
 * privacy coupling this factory exists specifically to avoid) while still
 * being AndroidKeyStore-encrypted-at-rest, noBackupFilesDir-excluded, and
 * exposed only through [ClientKeyRepository]'s own narrow contract (public
 * key freely, private key only just-in-time for tunnel construction, never
 * for display/logging - see that interface's own docs).
 */
object PrivateGatewayKeyRepositoryFactory {
    private const val KEY_ALIAS = "net.pocvpn.client.identity.privategateway.aesgcm.v1"
    private const val FILE_NAME = "private_gateway_identity.bin"

    fun create(context: Context): ClientKeyRepository {
        val store = FileIdentityStore(context.applicationContext.noBackupFilesDir, FILE_NAME)
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return AwgClientKeyRepository(store, encryptor)
    }
}
