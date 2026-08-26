package net.pocvpn.client.vpn.config

/** A single AmneziaWG peer (the gateway) to connect to. */
data class AwgPeer(
    val publicKeyBase64: String,
    val endpointHost: String,
    val endpointPort: Int,
    val allowedIps: List<String> = listOf("0.0.0.0/0", "::/0"),
    val persistentKeepaliveSeconds: Int? = 25,
)

/**
 * Full AmneziaWG interface + single-peer config for the POC.
 * privateKeyBase64 is expected to already be decrypted by the caller
 * (from Android Keystore-backed storage) - it is held only in memory here,
 * for the duration of a single connect() call, and is never logged.
 */
data class AwgConfig(
    val privateKeyBase64: String,
    val localAddresses: List<String>,
    val dnsServers: List<String>,
    val listenPort: Int? = null,
    val mtu: Int? = null,
    val profile: AwgProfile,
    val peer: AwgPeer,
)

/** Transport-agnostic config passed into VpnTransport.connect(). */
sealed class TransportConfig {
    data class Awg(val config: AwgConfig) : TransportConfig()
}
