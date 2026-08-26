package net.pocvpn.client.vpn.config

/**
 * Local, transport-owned representation of AmneziaWG's obfuscation/timing
 * parameters. This is the only place outside AmneziaWgTransport/AwgConfigMapper
 * that knows these field names - the rest of the app deals in TransportConfig.
 *
 * Field names mirror org.amnezia.awg.config.Interface's setters (verified
 * against the pinned v3.1.20260814 source in B2.6), not upstream documentation.
 */
data class AwgProfile(
    val junkPacketCount: Int? = null,
    val junkPacketMinSize: Int? = null,
    val junkPacketMaxSize: Int? = null,
    val initPacketJunkSize: Int? = null,
    val responsePacketJunkSize: Int? = null,
    val cookieReplyPacketJunkSize: Int? = null,
    val transportPacketJunkSize: Int? = null,
    val initPacketMagicHeader: String? = null,
    val responsePacketMagicHeader: String? = null,
    val underloadPacketMagicHeader: String? = null,
    val transportPacketMagicHeader: String? = null,
    val specialJunkI1: String? = null,
    val specialJunkI2: String? = null,
    val specialJunkI3: String? = null,
    val specialJunkI4: String? = null,
    val specialJunkI5: String? = null,
    val headerProtectionKeyBase64: String? = null,
    val contentPaddingAddition: String? = null,
    val randomTrailers: Boolean? = null,
    val disableCookies: Boolean? = null,
    val rekeyAfterTime: String? = null,
    val rekeyTimeout: String? = null,
    val rejectAfterTime: String? = null,
    val keepaliveTimeout: String? = null,
    val maxHandshakeAttempts: String? = null,
) {
    companion object {
        /** No AWG obfuscation fields set - plain WireGuard-compatible behavior, useful as a diagnostic baseline. */
        fun none(): AwgProfile = AwgProfile()
    }
}
