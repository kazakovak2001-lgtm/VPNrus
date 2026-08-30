package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileRepositoryFactory]: same
 * noBackupFilesDir convention, a DIFFERENT AndroidKeyStore alias (its own
 * key, never shared with the REALITY profile's) and a different backing
 * file (see [FileXrayTlsProfileStore]'s default fileName) so the two
 * profile types are fully independent.
 *
 * B13 - same endpoint-scoping/migration contract as
 * [XrayProfileRepositoryFactory.create] - see its own docs (including the
 * audit-fix note on why [migrateFromLegacyUnscopedFile] safely defaults to
 * true for the production endpoint rather than needing one blessed caller).
 */
object XrayTlsProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_tls_profile_key"
    private const val LEGACY_UNSCOPED_FILE_NAME = "xray_tls_profile.bin"
    private val PRODUCTION_ENDPOINT_ID = EndpointId(net.pocvpn.client.smartconnect.ProductionGateway.ID)

    fun create(
        context: Context,
        endpointId: EndpointId = PRODUCTION_ENDPOINT_ID,
        migrateFromLegacyUnscopedFile: Boolean = endpointId == PRODUCTION_ENDPOINT_ID,
    ): XrayTlsProfileRepository {
        val store = FileXrayTlsProfileStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
            legacyFileName = if (migrateFromLegacyUnscopedFile) LEGACY_UNSCOPED_FILE_NAME else null,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayTlsProfileRepository(store, encryptor)
    }
}
