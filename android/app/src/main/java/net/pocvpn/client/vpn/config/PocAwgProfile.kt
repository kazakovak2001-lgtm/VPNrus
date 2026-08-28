package net.pocvpn.client.vpn.config

/**
 * The one declared POC-01 AmneziaWG profile.
 *
 * B8B3B correction: S1-S4/H1-H4 below are pinned to the LIVE Oracle awg0
 * server's actual values (confirmed live, not the gateway/config/awg-profile.env
 * template - that file's declared values had drifted from what is actually
 * running) - AmneziaWG's receive-side packet-type/padding parsing depends on
 * these matching, so a mismatch here is a real handshake blocker, not a
 * client-side-only cosmetic difference. Jc/Jmin/Jmax are unaffected by this
 * fix (client-only tuning, not the server-dependent mismatch) and are left
 * exactly as before.
 */
object PocAwgProfile {
    val value = AwgProfile(
        junkPacketCount = 6,
        junkPacketMinSize = 40,
        junkPacketMaxSize = 100,
        initPacketJunkSize = 113,
        responsePacketJunkSize = 159,
        cookieReplyPacketJunkSize = 0,
        transportPacketJunkSize = 0,
        initPacketMagicHeader = "1106684696",
        responsePacketMagicHeader = "3677857287",
        underloadPacketMagicHeader = "353316806",
        transportPacketMagicHeader = "2068198996",
        randomTrailers = false,
        disableCookies = false,
        // headerProtectionKeyBase64 intentionally unset for POC-01 - see gateway/README.md.
    )
}
