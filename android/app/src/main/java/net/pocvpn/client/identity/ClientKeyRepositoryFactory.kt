package net.pocvpn.client.identity

import android.content.Context

/** Wires the real Android-backed ClientKeyRepository (AndroidKeyStore + noBackupFilesDir). */
object ClientKeyRepositoryFactory {
    private const val KEY_ALIAS = "net.pocvpn.client.identity.aesgcm.v1"

    fun create(context: Context): ClientKeyRepository {
        // noBackupFilesDir is excluded from Auto Backup - a restored ciphertext would be
        // undecryptable anyway since the AndroidKeyStore key is device-bound (see B4 notes).
        val store = FileIdentityStore(context.applicationContext.noBackupFilesDir)
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return AwgClientKeyRepository(store, encryptor)
    }
}
