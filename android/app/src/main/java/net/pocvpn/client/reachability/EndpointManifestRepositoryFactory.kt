package net.pocvpn.client.reachability

import android.content.Context

/**
 * B11 - real Android wiring for [EndpointManifestRepository]/[PathHistoryStore]/
 * [AndroidKeystoreFingerprintKeyProvider], mirroring
 * XrayTlsProfileRepositoryFactory's noBackupFilesDir + dedicated-KeyStore-alias
 * convention: durable storage lives under noBackupFilesDir (device-bound
 * anyway, matching TLS/REALITY profile storage), and this module's KeyStore
 * alias is its own, never shared with identity's AES-GCM key alias.
 */
object EndpointManifestRepositoryFactory {
    private const val FINGERPRINT_KEY_ALIAS = "nova_network_fingerprint_key"

    fun createManifestRepository(context: Context): EndpointManifestRepository {
        val directory = context.applicationContext.noBackupFilesDir
        val lkgStore = FileLastKnownGoodManifestStore(directory)
        return EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = EmbeddedBootstrapManifest.trustAnchors(),
            lkgStore = lkgStore,
            bootstrapManifest = EmbeddedBootstrapManifest.signedManifest(),
            nowEpochMillis = { System.currentTimeMillis() },
        )
    }

    fun createPathHistoryStore(context: Context): PathHistoryStore =
        FilePathHistoryStore(context.applicationContext.noBackupFilesDir)

    fun createFingerprintKeyProvider(context: Context): NetworkFingerprintKeyProvider =
        fingerprintKeyProvider(AndroidKeystoreFingerprintKeyProvider(FINGERPRINT_KEY_ALIAS))
}
