package net.pocvpn.client.relay

import android.content.Context
import net.pocvpn.client.identity.AndroidKeystoreAesGcmEncryptor

/**
 * B26 (task A) - wires the real Android-backed [FileIngressProfileStore]:
 * same noBackupFilesDir convention as [net.pocvpn.client.identity.XrayProfileRepositoryFactory],
 * its own dedicated AndroidKeyStore alias (never the managed-network Xray
 * profile's key material, even though both are AES-256-GCM - see
 * [FileIngressProfileStore]'s own docs for why these must stay separate).
 */
object IngressProfileStoreFactory {
    private const val KEY_ALIAS = "nova_ingress_profile_key"

    fun create(context: Context): IngressProfileStore = FileIngressProfileStore(
        directory = context.applicationContext.noBackupFilesDir,
        encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS),
    )
}
