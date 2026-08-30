package net.pocvpn.client.identity

import android.content.Context

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileRepositoryFactory]: same
 * noBackupFilesDir convention, a DIFFERENT AndroidKeyStore alias (its own
 * key, never shared with the REALITY profile's) and a different backing
 * file (see [FileXrayTlsProfileStore]'s default fileName) so the two
 * profile types are fully independent.
 */
object XrayTlsProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_tls_profile_key"

    fun create(context: Context): XrayTlsProfileRepository {
        val store = FileXrayTlsProfileStore(context.applicationContext.noBackupFilesDir)
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayTlsProfileRepository(store, encryptor)
    }
}
