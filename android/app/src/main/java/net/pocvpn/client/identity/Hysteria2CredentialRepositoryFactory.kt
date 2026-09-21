package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * B46-4A - wires the real Android-backed Hysteria2CredentialRepository:
 * mirrors [Shadowsocks2022CredentialRepositoryFactory] exactly - the same
 * `noBackupFilesDir` convention and AndroidKeyStore-backed [AesGcmKeyEncryptor]
 * every other credential/identity store in this package already uses.
 *
 * A DEDICATED key alias - never [Shadowsocks2022CredentialRepositoryFactory]'s
 * `"net.pocvpn.client.identity.shadowsocks2022.aesgcm.v1"`,
 * `XrayProfileRepositoryFactory`'s `"nova_xray_profile_key"`, or
 * `ClientKeyRepositoryFactory`'s AWG alias - so a Hysteria2 credential and
 * every other transport's credential are independently rotatable/revocable
 * Keystore keys, never sharing one (per-task requirement: "Do not reuse
 * Xray, AWG or Shadowsocks Keystore aliases").
 *
 * No legacy/migration path: there is no production Hysteria2 credential
 * format that ever existed before this factory - production storage starts
 * empty and is provisioned explicitly by [Hysteria2ProfileProvisioner].
 */
object Hysteria2CredentialRepositoryFactory {
    private const val KEY_ALIAS = "net.pocvpn.client.identity.hysteria2.aesgcm.v1"

    fun create(context: Context, endpointId: EndpointId): Hysteria2CredentialRepository {
        val store = FileHysteria2CredentialStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureHysteria2CredentialRepository(endpointId, store, encryptor)
    }
}
