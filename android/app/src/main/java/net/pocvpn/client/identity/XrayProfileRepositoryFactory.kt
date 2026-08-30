package net.pocvpn.client.identity

import android.content.Context
import net.pocvpn.client.reachability.EndpointId

/**
 * B8K4B - wires the real Android-backed XrayProfileRepository: same
 * noBackupFilesDir convention as ClientKeyRepositoryFactory, and the SAME
 * AndroidKeyStore alias ("nova_xray_profile_key") NovaXrayVpnService's own
 * inline factory already uses, so a profile saved through this factory is
 * the exact same encrypted file NovaXrayVpnService later reads - not a
 * second, independent store.
 *
 * B13 - [endpointId] scopes the backing file (see [FileXrayProfileStore]).
 *
 * B13 (audit fix) - [migrateFromLegacyUnscopedFile] now DEFAULTS to true
 * whenever [endpointId] is the production endpoint (the only endpoint that
 * ever had a real profile persisted under the old unscoped file name), and
 * false for any other endpoint - a caller no longer has to be "the one
 * blessed call site" to converge correctly. This is deliberately safe to
 * enable at every such call site, not just one, because migration itself is
 * idempotent (a no-op once the scoped file exists) and race-safe under
 * concurrent readers (`File.renameTo` is atomic; a "losing" concurrent
 * caller's rename simply fails silently because the source is already gone,
 * and its very next `file.exists()` check then sees the winner's result) -
 * see `FileXrayProfileStore.migrateLegacyIfNeeded`'s own docs and
 * `XrayProfileRepositoryTest`'s concurrent-readers regression test. Fixes a
 * real gap: NovaXrayVpnService/XrayDiagnosticsActivity each construct their
 * OWN repository instance via this factory's defaults - before this fix,
 * neither carried the migration flag, so either one starting first (e.g. a
 * debug developer opening XrayDiagnosticsActivity directly, or in principle
 * any first reader that isn't MainViewModel) would see a legacy profile as
 * simply missing instead of migrating it.
 */
object XrayProfileRepositoryFactory {
    private const val KEY_ALIAS = "nova_xray_profile_key"
    private const val LEGACY_UNSCOPED_FILE_NAME = "xray_profile.bin"
    private val PRODUCTION_ENDPOINT_ID = EndpointId(net.pocvpn.client.smartconnect.ProductionGateway.ID)

    fun create(
        context: Context,
        endpointId: EndpointId = PRODUCTION_ENDPOINT_ID,
        migrateFromLegacyUnscopedFile: Boolean = endpointId == PRODUCTION_ENDPOINT_ID,
    ): XrayProfileRepository {
        val store = FileXrayProfileStore(
            directory = context.applicationContext.noBackupFilesDir,
            endpointId = endpointId,
            legacyFileName = if (migrateFromLegacyUnscopedFile) LEGACY_UNSCOPED_FILE_NAME else null,
        )
        val encryptor = AndroidKeystoreAesGcmEncryptor(KEY_ALIAS)
        return SecureXrayProfileRepository(store, encryptor)
    }
}
