package net.pocvpn.client.identity

import android.content.Context

/**
 * B8K4B - wires the real Android-backed XrayProfileRepository: same
 * noBackupFilesDir convention as ClientKeyRepositoryFactory, and the SAME
 * AndroidKeyStore alias ("nova_xray_profile_key") NovaXrayVpnService's own
 * inline factory already uses, so a profile saved through this factory is
 * the exact same encrypted file NovaXrayVpnService later reads - not a
 * second, independent store.
 */
object XrayProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_profile_key"

    fun create(context: Context): XrayProfileRepository {
        val store = FileXrayProfileStore(context.applicationContext.noBackupFilesDir)
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayProfileRepository(store, encryptor)
    }
}
