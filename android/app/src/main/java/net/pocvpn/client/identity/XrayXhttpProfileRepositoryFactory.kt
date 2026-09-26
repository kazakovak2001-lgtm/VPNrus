package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * B61 - the XHTTP counterpart of [XrayTlsProfileRepositoryFactory]: same
 * noBackupFilesDir convention, a DIFFERENT AndroidKeyStore alias (its own
 * key, never shared with REALITY/TLS) and a different backing file (see
 * [FileXrayXhttpProfileStore]'s default fileName), so all three profile
 * types are fully independent. No legacy-unscoped-file migration - unlike
 * REALITY/TLS, no pre-B61 unscoped XHTTP profile file has ever existed.
 */
object XrayXhttpProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_xhttp_profile_key"
    private val PRODUCTION_ENDPOINT_ID = EndpointId(net.pocvpn.client.smartconnect.ProductionGateway.ID)

    fun create(
        context: Context,
        endpointId: EndpointId = PRODUCTION_ENDPOINT_ID,
    ): XrayXhttpProfileRepository {
        val store = FileXrayXhttpProfileStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayXhttpProfileRepository(store, encryptor)
    }
}
