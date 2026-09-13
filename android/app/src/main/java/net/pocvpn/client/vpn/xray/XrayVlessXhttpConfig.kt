package net.pocvpn.client.vpn.xray

/**
 * B35 - resolved VLESS + TLS + XHTTP wire configuration for pinned
 * Xray-core v26.7.28. This is not provider metadata and contains no generic
 * pass-through map: every emitted field is explicitly modeled and audited.
 */
data class XrayVlessXhttpConfig(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val tlsServerName: String,
    val fingerprint: String,
    val minimumTlsVersion: XrayXhttpMinimumTlsVersion,
    /** Foundation execution supports one deterministic ALPN only. */
    val alpn: String,
    /** HTTP Host sent to the CDN edge; deliberately distinct from origin Host policy. */
    val xhttpHost: String,
    /** Signed normalized base path; static query parameters are stored separately. */
    val xhttpPath: String,
    val queryParameters: Map<String, String>,
    val headers: Map<String, String>,
    val mode: XrayXhttpMode,
    val uplinkHttpMethod: XrayXhttpUplinkHttpMethod,
    val maxEachPostBytes: Int,
    val paddingPlacement: XrayXhttpPaddingPlacement,
    val paddingMinBytes: Int,
    val paddingMaxBytes: Int,
    val mtu: Int = XrayVlessRealityConfig.DEFAULT_MTU,
    val dnsServers: List<String> = XrayVlessRealityConfig.DEFAULT_DNS_SERVERS,
    val tunLocalAddressIpv4: String = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_ADDRESS_IPV4,
    val tunLocalPrefixLengthIpv4: Int = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4,
) {
    override fun toString(): String = "XrayVlessXhttpConfig(" +
        "server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "tlsServerName=$tlsServerName, fingerprint=$fingerprint, " +
        "minimumTlsVersion=$minimumTlsVersion, alpn=$alpn, " +
        "xhttpHost=$xhttpHost, xhttpPath=$xhttpPath, " +
        "queryParameterCount=${queryParameters.size}, headerCount=${headers.size}, " +
        "mode=$mode, uplinkHttpMethod=$uplinkHttpMethod, " +
        "maxEachPostBytes=$maxEachPostBytes, paddingPlacement=$paddingPlacement, " +
        "paddingMinBytes=$paddingMinBytes, paddingMaxBytes=$paddingMaxBytes, " +
        "mtu=$mtu, dnsServers=$dnsServers, " +
        "tunLocalAddressIpv4=$tunLocalAddressIpv4, " +
        "tunLocalPrefixLengthIpv4=$tunLocalPrefixLengthIpv4)"
}

enum class XrayXhttpMode(val wireValue: String) {
    AUTO("auto"),
    PACKET_UP("packet-up"),
    STREAM_UP("stream-up"),
    STREAM_ONE("stream-one"),
}

enum class XrayXhttpUplinkHttpMethod(val wireValue: String) {
    GET("GET"),
    POST("POST"),
    PUT("PUT"),
    HEAD("HEAD"),
}

enum class XrayXhttpPaddingPlacement(val wireValue: String) {
    HEADER("header"),
    QUERY("query"),
}

enum class XrayXhttpMinimumTlsVersion(val wireValue: String) {
    TLS_1_2("1.2"),
    TLS_1_3("1.3"),
}

enum class XrayXhttpConfigValidationError {
    BLANK_SERVER,
    INVALID_PORT,
    INVALID_UUID,
    INVALID_TLS_SERVER_NAME,
    UNSUPPORTED_FINGERPRINT,
    UNSUPPORTED_ALPN,
    INVALID_XHTTP_HOST,
    INVALID_XHTTP_PATH,
    INVALID_QUERY_PARAMETERS,
    INVALID_HEADERS,
    INVALID_MODE_METHOD_COMBINATION,
    INVALID_POST_LIMIT,
    INVALID_PADDING_RANGE,
    INVALID_MTU,
    INVALID_TUN_LOCAL_ADDRESS,
}

sealed interface XrayXhttpConfigValidationResult {
    data class Valid(val config: XrayVlessXhttpConfig) : XrayXhttpConfigValidationResult
    data class Invalid(val errors: Set<XrayXhttpConfigValidationError>) : XrayXhttpConfigValidationResult
}

private val XHTTP_UUID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)
private val XHTTP_IPV4_REGEX = Regex(
    "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$",
)
private val XHTTP_PARAMETER_KEY_REGEX = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
private val XHTTP_SUPPORTED_FINGERPRINTS = setOf("chrome", "firefox", "safari", "edge")
private val XHTTP_SUPPORTED_ALPN = setOf("h2", "h3", "http/1.1")
private val XHTTP_RESERVED_HEADERS = setOf(
    "authorization", "proxy-authorization", "cookie", "set-cookie", "host",
    "content-length", "transfer-encoding", "connection", "upgrade",
)

fun validateXrayVlessXhttpConfig(config: XrayVlessXhttpConfig): XrayXhttpConfigValidationResult {
    val errors = linkedSetOf<XrayXhttpConfigValidationError>()

    if (config.server.isBlank()) errors += XrayXhttpConfigValidationError.BLANK_SERVER
    if (config.serverPort !in 1..65535) errors += XrayXhttpConfigValidationError.INVALID_PORT
    if (!XHTTP_UUID_REGEX.matches(config.uuid)) errors += XrayXhttpConfigValidationError.INVALID_UUID
    if (!isXhttpHostname(config.tlsServerName)) errors += XrayXhttpConfigValidationError.INVALID_TLS_SERVER_NAME
    if (config.fingerprint !in XHTTP_SUPPORTED_FINGERPRINTS) {
        errors += XrayXhttpConfigValidationError.UNSUPPORTED_FINGERPRINT
    }
    if (config.alpn !in XHTTP_SUPPORTED_ALPN) errors += XrayXhttpConfigValidationError.UNSUPPORTED_ALPN
    if (!isXhttpHostname(config.xhttpHost)) errors += XrayXhttpConfigValidationError.INVALID_XHTTP_HOST
    if (!isXhttpPath(config.xhttpPath)) errors += XrayXhttpConfigValidationError.INVALID_XHTTP_PATH
    if (!validXhttpParameters(config.queryParameters)) {
        errors += XrayXhttpConfigValidationError.INVALID_QUERY_PARAMETERS
    }
    if (!validXhttpHeaders(config.headers)) errors += XrayXhttpConfigValidationError.INVALID_HEADERS
    if (config.uplinkHttpMethod == XrayXhttpUplinkHttpMethod.GET && config.mode != XrayXhttpMode.PACKET_UP) {
        errors += XrayXhttpConfigValidationError.INVALID_MODE_METHOD_COMBINATION
    }
    if (config.maxEachPostBytes <= 0) errors += XrayXhttpConfigValidationError.INVALID_POST_LIMIT

    // Pinned v26.7.28 has no "padding disabled" representation:
    // absent/zero xPaddingBytes normalizes to 100..1000. This executable
    // type therefore represents only explicit positive padding.
    val validPadding =
        config.paddingMinBytes in 1..65536 &&
            config.paddingMaxBytes in config.paddingMinBytes..65536
    if (!validPadding) errors += XrayXhttpConfigValidationError.INVALID_PADDING_RANGE
    if (config.mtu !in 1280..65535) errors += XrayXhttpConfigValidationError.INVALID_MTU
    if (!XHTTP_IPV4_REGEX.matches(config.tunLocalAddressIpv4)) {
        errors += XrayXhttpConfigValidationError.INVALID_TUN_LOCAL_ADDRESS
    }

    return if (errors.isEmpty()) {
        XrayXhttpConfigValidationResult.Valid(config)
    } else {
        XrayXhttpConfigValidationResult.Invalid(errors)
    }
}

private fun isXhttpHostname(value: String): Boolean =
    value.length in 1..253 &&
        value.any { it.isLetter() } &&
        value.split('.').all { label ->
            label.length in 1..63 &&
                label.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"))
        }

private fun isXhttpPath(value: String): Boolean =
    value.length in 1..512 &&
        value.startsWith('/') &&
        !value.startsWith("//") &&
        value.endsWith('/') &&
        value.all { it.code in 33..126 } &&
        '?' !in value &&
        '#' !in value &&
        '\\' !in value

private fun validXhttpParameters(values: Map<String, String>): Boolean =
    values.size <= 16 &&
        values.all { (key, value) ->
            XHTTP_PARAMETER_KEY_REGEX.matches(key) &&
                value.length <= 256 &&
                value.all { it.code in 32..126 }
        }

private fun validXhttpHeaders(values: Map<String, String>): Boolean =
    validXhttpParameters(values) &&
        values.keys.map { it.lowercase(java.util.Locale.ROOT) }.toSet().size == values.size &&
        values.keys.none { it.lowercase(java.util.Locale.ROOT) in XHTTP_RESERVED_HEADERS }
