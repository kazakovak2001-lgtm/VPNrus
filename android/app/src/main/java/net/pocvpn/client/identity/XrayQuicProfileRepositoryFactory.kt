package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/** B21 - the QUIC counterpart of [XrayTlsProfileRepositoryFactory]: same noBackupFilesDir convention, its own AndroidKeyStore alias/backing file so REALITY/TLS_TCP/QUIC profiles are three fully independent, simultaneously-persistable records. */
object XrayQuicProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_quic_profile_key"
    private val PRODUCTION_ENDPOINT_ID = EndpointId(net.pocvpn.client.smartconnect.ProductionGateway.ID)

    fun create(
        context: Context,
        endpointId: EndpointId = PRODUCTION_ENDPOINT_ID,
    ): XrayQuicProfileRepository {
        val store = FileXrayQuicProfileStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayQuicProfileRepository(store, encryptor)
    }
}
