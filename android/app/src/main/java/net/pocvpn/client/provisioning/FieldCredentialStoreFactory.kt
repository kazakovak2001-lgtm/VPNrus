package net.pocvpn.client.provisioning

import android.content.Context
import net.pocvpn.client.identity.AndroidKeystoreAesGcmEncryptor
import java.io.File

/**
 * Russia field-test zero-touch enrollment - wires the real Android-backed
 * [FileFieldCredentialStore]: same noBackupFilesDir convention as
 * [net.pocvpn.client.relay.IngressProfileStoreFactory], its own dedicated
 * AndroidKeyStore alias (never the ingress credential's or the managed-
 * network Xray profile's key material, even though all are AES-256-GCM).
 */
object FieldCredentialStoreFactory {
    private const val KEY_ALIAS = "nova_field_enrollment_credential_key"
    private const val FILE_NAME = "field_enrollment_credential.bin"

    fun create(context: Context): FieldCredentialStore = FileFieldCredentialStore(
        file = File(context.applicationContext.noBackupFilesDir, FILE_NAME),
        encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS),
    )
}
