package net.pocvpn.client.vpn.xray

/**
 * Client config for VLESS over XHTTP secured by REALITY - rendered by
 * [XrayConfigRenderer.render] into a `network: xhttp`, `security: reality`
 * outbound. The REALITY fields are those of [XrayVlessRealityConfig]
 * without `flow` (XTLS Vision is not valid over XHTTP); the XHTTP fields
 * are only the path, mode and uplink method the server sends. No TLS
 * server name, ALPN, host header or padding: REALITY owns the handshake
 * and Xray-core's own XHTTP defaults apply.
 */
data class XrayVlessRealityXhttpConfig(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
    val realityPublicKey: String,
    val shortId: String,
    val xhttpPath: String,
    val mode: XrayXhttpMode,
    val uplinkHttpMethod: XrayXhttpUplinkHttpMethod,
    val mtu: Int = XrayVlessRealityConfig.DEFAULT_MTU,
    val dnsServers: List<String> = XrayVlessRealityConfig.DEFAULT_DNS_SERVERS,
    val tunLocalAddressIpv4: String = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_ADDRESS_IPV4,
    val tunLocalPrefixLengthIpv4: Int = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4,
) {
    override fun toString(): String = "XrayVlessRealityXhttpConfig(" +
        "server=$server, serverPort=$serverPort, uuid=<redacted>, serverName=$serverName, " +
        "fingerprint=$fingerprint, realityPublicKey=<redacted>, shortId=<redacted>, " +
        "xhttpPath=$xhttpPath, mode=$mode, uplinkHttpMethod=$uplinkHttpMethod, mtu=$mtu, " +
        "dnsServers=$dnsServers, tunLocalAddressIpv4=$tunLocalAddressIpv4, " +
        "tunLocalPrefixLengthIpv4=$tunLocalPrefixLengthIpv4)"

    /** The REALITY half as an [XrayVlessRealityConfig] with no flow - used only to reuse its validator. */
    internal fun realityPart(): XrayVlessRealityConfig = XrayVlessRealityConfig(
        server = server,
        serverPort = serverPort,
        uuid = uuid,
        flow = "",
        serverName = serverName,
        fingerprint = fingerprint,
        realityPublicKey = realityPublicKey,
        shortId = shortId,
        mtu = mtu,
        dnsServers = dnsServers,
        tunLocalAddressIpv4 = tunLocalAddressIpv4,
        tunLocalPrefixLengthIpv4 = tunLocalPrefixLengthIpv4,
    )
}

sealed class XrayRealityXhttpValidationResult {
    data class Valid(val config: XrayVlessRealityXhttpConfig) : XrayRealityXhttpValidationResult()

    /** [realityErrors] from [validateXrayVlessRealityConfig]; [invalidPath] when the XHTTP path is not `/.../`. */
    data class Invalid(
        val realityErrors: List<XrayConfigValidationError>,
        val invalidPath: Boolean,
    ) : XrayRealityXhttpValidationResult()
}

/**
 * Validates the REALITY half with the SAME [validateXrayVlessRealityConfig]
 * every REALITY session uses (never a second copy of those rules) and the
 * XHTTP path with the shape the gateway enforces (`/` at both ends).
 */
fun validateXrayVlessRealityXhttpConfig(config: XrayVlessRealityXhttpConfig): XrayRealityXhttpValidationResult {
    val realityErrors = when (val result = validateXrayVlessRealityConfig(config.realityPart())) {
        is XrayConfigValidationResult.Valid -> emptyList()
        is XrayConfigValidationResult.Invalid -> result.errors
    }
    val invalidPath = !config.xhttpPath.startsWith("/") || !config.xhttpPath.endsWith("/")
    return if (realityErrors.isEmpty() && !invalidPath) {
        XrayRealityXhttpValidationResult.Valid(config)
    } else {
        XrayRealityXhttpValidationResult.Invalid(realityErrors, invalidPath)
    }
}
