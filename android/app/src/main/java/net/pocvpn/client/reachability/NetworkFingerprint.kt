package net.pocvpn.client.reachability

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.pocvpn.client.network.NetworkType

/**
 * Coarse, ALREADY non-identifying-by-itself network properties - deliberately
 * excludes SSID/BSSID/IMSI/phone number/DNS query history. [dnsServerAddresses]
 * are resolver IPs (already exposed via LinkProperties for routing purposes
 * elsewhere in this codebase), not a destination or query - see
 * NetworkFingerprinter's own docs for why HMAC'ing even this coarse signal
 * still isn't a global tracking id.
 */
data class CoarseNetworkSignals(
    val networkType: NetworkType,
    val dnsServerAddresses: List<String>,
)

/**
 * B11 - a LOCAL-ONLY, per-install network identity for connection memory
 * (networkFingerprint x endpointId x transportKind - see PathHistoryStore).
 * Deliberately NOT a globally reusable tracking identifier:
 *
 *  - The HMAC key is generated on-device, non-exportable (AndroidKeyStore in
 *    production - see AndroidKeystoreHmacFingerprintKeyProvider), and unique
 *    per app install. Nobody outside this app instance can compute the same
 *    fingerprint for the same network, including this app's own backend.
 *  - The output is truncated to [FINGERPRINT_HEX_LENGTH] hex chars - enough
 *    to distinguish networks locally, not an attempt at a globally unique id.
 *  - Only the fingerprint STRING is ever persisted (see PathHistoryStore) -
 *    [CoarseNetworkSignals] itself never reaches disk.
 */
object NetworkFingerprinter {
    private const val FINGERPRINT_HEX_LENGTH = 16
    private const val HMAC_ALGORITHM = "HmacSHA256"

    fun fingerprint(signals: CoarseNetworkSignals, hmacKeyBytes: ByteArray): String {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        mac.init(SecretKeySpec(hmacKeyBytes, HMAC_ALGORITHM))
        mac.update(signals.networkType.name.toByteArray(Charsets.UTF_8))
        mac.update(0)
        signals.dnsServerAddresses.sorted().forEach {
            mac.update(it.toByteArray(Charsets.UTF_8))
            mac.update(0)
        }
        val digest = mac.doFinal()
        return digest.joinToString("") { "%02x".format(it) }.take(FINGERPRINT_HEX_LENGTH)
    }
}

/** Supplies the raw HMAC key bytes - real Android impl backs this with a non-exportable AndroidKeyStore key, never exposing the key itself past this boundary. */
fun interface NetworkFingerprintKeyProvider {
    fun keyBytes(): ByteArray
}
