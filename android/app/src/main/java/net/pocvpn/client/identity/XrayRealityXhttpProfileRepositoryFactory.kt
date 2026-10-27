package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * The REALITY + XHTTP counterpart of [XrayXhttpProfileRepositoryFactory]:
 * same noBackupFilesDir convention, its OWN AndroidKeyStore alias (never
 * shared with REALITY/TLS/XHTTP) and its own backing file (see
 * [FileXrayRealityXhttpProfileStore]'s default fileName). No legacy
 * migration - no earlier file of this kind has ever existed.
 */
object XrayRealityXhttpProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_reality_xhttp_profile_key"
    private val PRODUCTION_ENDPOINT_ID = EndpointId(net.pocvpn.client.smartconnect.ProductionGateway.ID)

    fun create(
        context: Context,
        endpointId: EndpointId = PRODUCTION_ENDPOINT_ID,
    ): XrayRealityXhttpProfileRepository {
        val store = FileXrayRealityXhttpProfileStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayRealityXhttpProfileRepository(store, encryptor)
    }
}
