package net.pocvpn.client.provisioning

import android.content.Context
import net.pocvpn.client.identity.AndroidKeystoreAesGcmEncryptor

/**
 * Russia field-test zero-touch enrollment - wires the real Android-backed
 * [FileFieldCredentialStore]: same noBackupFilesDir convention as
 * [net.pocvpn.client.relay.IngressProfileStoreFactory], its own dedicated
 * AndroidKeyStore alias (never the ingress credential's or the managed-
 * network Xray profile's key material, even though all are AES-256-GCM).
 * One file PER ENDPOINT HOST (see [FileFieldCredentialStore]'s own docs
 * for why - Germany/Stockholm/the Stockholm ingress role are separate
 * control planes with separate credentials).
 */
object FieldCredentialStoreFactory {
    private const val KEY_ALIAS = "nova_field_enrollment_credential_key"

    fun create(context: Context): FieldCredentialStore = FileFieldCredentialStore(
        directory = context.applicationContext.noBackupFilesDir,
        encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS),
    )
}
