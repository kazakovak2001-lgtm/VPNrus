package net.pocvpn.client.vpn.config

/**
 * The one declared POC-01 AmneziaWG profile, shared with the gateway.
 * Values here MUST match gateway/config/awg-profile.env exactly - see that
 * file and gateway/README.md's B5A section for which fields the protocol
 * actually requires to match (only HeaderProtectionKey, which POC-01 leaves
 * unset) versus which are declared identical here purely for consistency.
 */
object PocAwgProfile {
    val value = AwgProfile(
        junkPacketCount = 6,
        junkPacketMinSize = 40,
        junkPacketMaxSize = 100,
        initPacketJunkSize = 15,
        responsePacketJunkSize = 20,
        cookieReplyPacketJunkSize = 15,
        transportPacketJunkSize = 20,
        initPacketMagicHeader = "1190494288",
        responsePacketMagicHeader = "1190494289",
        underloadPacketMagicHeader = "1190494290",
        transportPacketMagicHeader = "1190494291",
        randomTrailers = false,
        disableCookies = false,
        // headerProtectionKeyBase64 intentionally unset for POC-01 - see gateway/README.md.
    )
}
