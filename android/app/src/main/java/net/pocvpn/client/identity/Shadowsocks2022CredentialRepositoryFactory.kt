package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * B45B-2 - wires the real Android-backed Shadowsocks2022CredentialRepository:
 * the same `noBackupFilesDir` convention (excluded from Auto Backup - a
 * restored ciphertext would be undecryptable anyway since the AndroidKeyStore
 * key is device-bound) and AndroidKeyStore-backed [AesGcmKeyEncryptor] every
 * other credential/identity store in this package already uses. A dedicated
 * key alias - never [XrayProfileRepositoryFactory]'s
 * `"nova_xray_profile_key"` or [ClientKeyRepositoryFactory]'s AWG alias - so
 * a Shadowsocks credential and an Xray profile are independently rotatable/
 * revocable Keystore keys, never sharing one.
 *
 * No legacy/migration path: there is no production Shadowsocks credential
 * format that ever existed before this factory (B45A's own
 * `b45a-dataplane.properties` is a debug-only, gitignored spike mechanism -
 * production storage starts empty and is provisioned explicitly by a future
 * slice, never imported from it).
 */
object Shadowsocks2022CredentialRepositoryFactory {
    private const val KEY_ALIAS = "net.pocvpn.client.identity.shadowsocks2022.aesgcm.v1"

    fun create(context: Context, endpointId: EndpointId): Shadowsocks2022CredentialRepository {
        val store = FileShadowsocks2022CredentialStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureShadowsocks2022CredentialRepository(endpointId, store, encryptor)
    }
}
