package net.pocvpn.client.vpn.xray

/**
 * B8K1B - typed VLESS+REALITY profile for the isolated Xray adapter shell.
 * Field names/shapes here are the Kotlin-side counterpart of the exact Xray
 * config JSON tags verified against the pinned xray-core v26.7.28 source in
 * docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md (infra/conf/vless.go's
 * VLessOutboundVnext/VLessOutboundTarget, infra/conf/transport_security.go's
 * client REALITYConfig, infra/conf/tun.go's Config) - see [XrayConfigRenderer]
 * for the actual JSON emission using these exact tag names.
 *
 * Deliberately excludes anything this slice does not use (fallbacks, mux,
 * sniffing, seed/testseed, non-REALITY security). No field here is a secret
 * the user typed in some other form - [uuid]/[realityPublicKey]/[shortId] are
 * the profile's real credential material and must never be logged; see the
 * redacted [toString] override below.
 */
data class XrayVlessRealityConfig(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    /** "" (no flow) or the single value xray-core's proxy/vless package actually implements: "xtls-rprx-vision". */
    val flow: String,
    val serverName: String,
    val fingerprint: String,
    val realityPublicKey: String,
    val shortId: String,
    val mtu: Int = DEFAULT_MTU,
    val dnsServers: List<String> = DEFAULT_DNS_SERVERS,
    /** The TUN interface's own point-to-point address (VpnService.Builder.addAddress), not a server-side value. */
    val tunLocalAddressIpv4: String = DEFAULT_TUN_LOCAL_ADDRESS_IPV4,
    val tunLocalPrefixLengthIpv4: Int = DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4,
) {
    /** Never expose uuid/realityPublicKey/shortId - this is what any accidental log/toString call sees instead. */
    override fun toString(): String = "XrayVlessRealityConfig(" +
        "server=$server, serverPort=$serverPort, uuid=<redacted>, flow=$flow, " +
        "serverName=$serverName, fingerprint=$fingerprint, realityPublicKey=<redacted>, " +
        "shortId=<redacted>, mtu=$mtu, dnsServers=$dnsServers, " +
        "tunLocalAddressIpv4=$tunLocalAddressIpv4, tunLocalPrefixLengthIpv4=$tunLocalPrefixLengthIpv4)"

    companion object {
        const val DEFAULT_MTU = 1420
        val DEFAULT_DNS_SERVERS = listOf("1.1.1.1", "8.8.8.8")
        const val DEFAULT_TUN_LOCAL_ADDRESS_IPV4 = "172.19.0.1"
        const val DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4 = 30
    }
}

/**
 * One reason a candidate [XrayVlessRealityConfig] is not acceptable to render
 * or connect with. Deliberately enumerated (not a bare string) so tests can
 * assert on the exact failure, not just "some error happened".
 */
sealed class XrayConfigValidationError {
    object BlankServer : XrayConfigValidationError()
    object InvalidPort : XrayConfigValidationError()
    object InvalidUuid : XrayConfigValidationError()
    object BlankServerName : XrayConfigValidationError()
    object UnsupportedFlow : XrayConfigValidationError()
    object UnsupportedFingerprint : XrayConfigValidationError()
    object InvalidRealityPublicKey : XrayConfigValidationError()
    object InvalidShortId : XrayConfigValidationError()
    object InvalidMtu : XrayConfigValidationError()
    object InvalidTunLocalAddress : XrayConfigValidationError()
}

sealed class XrayConfigValidationResult {
    data class Valid(val config: XrayVlessRealityConfig) : XrayConfigValidationResult()
    data class Invalid(val errors: List<XrayConfigValidationError>) : XrayConfigValidationResult()
}

// RFC 4122 textual form: 8-4-4-4-12 hex digits. xray-core's VLESS user "id"
// accepts this shape (it also accepts arbitrary strings hashed into a UUIDv5,
// but this adapter only ever stores/renders a real RFC 4122 UUID - never a
// raw passphrase - so validation is deliberately strict here).
private val UUID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)

// X25519 public key, url-safe base64 without padding: 32 raw bytes -> 43 chars.
private val REALITY_PUBLIC_KEY_REGEX = Regex("^[A-Za-z0-9_-]{43}$")

// REALITY short IDs are hex, even length, 0-16 hex chars per xray-core's
// REALITYConfig.ShortIds; this adapter requires a real (non-empty) one.
private val SHORT_ID_REGEX = Regex("^[0-9a-fA-F]{2,16}$")

// Confirmed against xray-core's proxy/vless package (proxy/vless/vless.go: XRV).
private val SUPPORTED_FLOWS = setOf("", "xtls-rprx-vision")

// Confirmed against xray-core's common/utils/browser.go uTLS fingerprint
// cases actually implemented there. Deliberately conservative - expand only
// after checking the pinned source, not from general uTLS documentation.
private val SUPPORTED_FINGERPRINTS = setOf("chrome", "firefox", "safari", "edge")

private const val MIN_PORT = 1
private const val MAX_PORT = 65535
private const val MIN_MTU = 1280 // smallest IPv6-safe MTU; xray-core's tun inbound does not itself enforce a floor
private const val MAX_MTU = 65535

private val IPV4_REGEX = Regex(
    "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$",
)

/** Pure validation - no I/O, no logging, safe to unit-test with only in-memory values. */
fun validateXrayVlessRealityConfig(config: XrayVlessRealityConfig): XrayConfigValidationResult {
    val errors = mutableListOf<XrayConfigValidationError>()

    if (config.server.isBlank()) errors += XrayConfigValidationError.BlankServer
    if (config.serverPort !in MIN_PORT..MAX_PORT) errors += XrayConfigValidationError.InvalidPort
    if (!UUID_REGEX.matches(config.uuid)) errors += XrayConfigValidationError.InvalidUuid
    if (config.serverName.isBlank()) errors += XrayConfigValidationError.BlankServerName
    if (config.flow !in SUPPORTED_FLOWS) errors += XrayConfigValidationError.UnsupportedFlow
    if (config.fingerprint !in SUPPORTED_FINGERPRINTS) errors += XrayConfigValidationError.UnsupportedFingerprint
    if (!REALITY_PUBLIC_KEY_REGEX.matches(config.realityPublicKey)) {
        errors += XrayConfigValidationError.InvalidRealityPublicKey
    }
    if (!SHORT_ID_REGEX.matches(config.shortId) || config.shortId.length % 2 != 0) {
        errors += XrayConfigValidationError.InvalidShortId
    }
    if (config.mtu !in MIN_MTU..MAX_MTU) errors += XrayConfigValidationError.InvalidMtu
    if (!IPV4_REGEX.matches(config.tunLocalAddressIpv4)) errors += XrayConfigValidationError.InvalidTunLocalAddress

    return if (errors.isEmpty()) {
        XrayConfigValidationResult.Valid(config)
    } else {
        XrayConfigValidationResult.Invalid(errors)
    }
}
