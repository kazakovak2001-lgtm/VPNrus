package net.pocvpn.client.vpn.xray

/**
 * B21 - typed VLESS+XHTTP(H3/QUIC) profile for the SAME isolated Xray
 * adapter shell [XrayVlessRealityConfig]/[XrayVlessTlsConfig] already use -
 * see docs/B21_QUIC_TRANSPORT_AUDIT.md for the pinned xray-core v26.7.28
 * source citation this is built from. Same TLS-style credential shape as
 * [XrayVlessTlsConfig] (no REALITY key material - the audit explains why
 * REALITY does not apply to a genuine QUIC/H3 transport) plus [path], the
 * XHTTP request path this gateway's inbound actually accepts - server-
 * issued, never hardcoded on the client (see [XrayConfigRenderer]'s own
 * docs for exactly how this renders).
 *
 * `TransportKind.QUIC` is NOT registered AVAILABLE anywhere until a real
 * profile exists for the target endpoint (same "isolated adapter shell"
 * precedent B8K1B/B8O2 already established) - this type exists so it CAN be
 * rendered and unit-tested end to end without any production port change.
 */
data class XrayVlessQuicConfig(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
    val path: String,
    val mtu: Int = XrayVlessRealityConfig.DEFAULT_MTU,
    val dnsServers: List<String> = XrayVlessRealityConfig.DEFAULT_DNS_SERVERS,
    /** The TUN interface's own point-to-point address (VpnService.Builder.addAddress), not a server-side value. */
    val tunLocalAddressIpv4: String = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_ADDRESS_IPV4,
    val tunLocalPrefixLengthIpv4: Int = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4,
) {
    /** Never expose uuid - this is what any accidental log/toString call sees instead. */
    override fun toString(): String = "XrayVlessQuicConfig(" +
        "server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "serverName=$serverName, fingerprint=$fingerprint, path=$path, mtu=$mtu, dnsServers=$dnsServers, " +
        "tunLocalAddressIpv4=$tunLocalAddressIpv4, tunLocalPrefixLengthIpv4=$tunLocalPrefixLengthIpv4)"
}

/** One reason a candidate [XrayVlessQuicConfig] is not acceptable to render or connect with - closed enum, not a bare string, same discipline as [XrayTlsConfigValidationError]. */
sealed class XrayQuicConfigValidationError {
    object BlankServer : XrayQuicConfigValidationError()
    object InvalidPort : XrayQuicConfigValidationError()
    object InvalidUuid : XrayQuicConfigValidationError()
    object BlankServerName : XrayQuicConfigValidationError()
    object UnsupportedFingerprint : XrayQuicConfigValidationError()
    object InvalidPath : XrayQuicConfigValidationError()
    object InvalidMtu : XrayQuicConfigValidationError()
    object InvalidTunLocalAddress : XrayQuicConfigValidationError()
}

sealed class XrayQuicConfigValidationResult {
    data class Valid(val config: XrayVlessQuicConfig) : XrayQuicConfigValidationResult()
    data class Invalid(val errors: List<XrayQuicConfigValidationError>) : XrayQuicConfigValidationResult()
}

/**
 * Pure validation - no I/O, no logging, safe to unit-test with only
 * in-memory values. Reuses the SAME UUID/fingerprint/MTU/tun-address rules
 * [validateXrayVlessTlsConfig] already enforces (re-declared here, not
 * shared, to keep TLS_TCP's own file/behavior completely untouched - same
 * reasoning that file's own docs already give for not sharing with
 * REALITY's). [path] must be a non-blank, absolute (leading `/`) HTTP path -
 * the shape xray-core's XHTTP `path` field expects.
 */
fun validateXrayVlessQuicConfig(config: XrayVlessQuicConfig): XrayQuicConfigValidationResult {
    val errors = mutableListOf<XrayQuicConfigValidationError>()

    if (config.server.isBlank()) errors += XrayQuicConfigValidationError.BlankServer
    if (config.serverPort !in 1..65535) errors += XrayQuicConfigValidationError.InvalidPort
    if (!QUIC_UUID_REGEX.matches(config.uuid)) errors += XrayQuicConfigValidationError.InvalidUuid
    if (config.serverName.isBlank()) errors += XrayQuicConfigValidationError.BlankServerName
    if (config.fingerprint !in QUIC_SUPPORTED_FINGERPRINTS) errors += XrayQuicConfigValidationError.UnsupportedFingerprint
    if (!QUIC_PATH_REGEX.matches(config.path)) errors += XrayQuicConfigValidationError.InvalidPath
    if (config.mtu !in 1280..65535) errors += XrayQuicConfigValidationError.InvalidMtu
    if (!QUIC_IPV4_REGEX.matches(config.tunLocalAddressIpv4)) errors += XrayQuicConfigValidationError.InvalidTunLocalAddress

    return if (errors.isEmpty()) {
        XrayQuicConfigValidationResult.Valid(config)
    } else {
        XrayQuicConfigValidationResult.Invalid(errors)
    }
}

// Same rule as XrayVlessRealityConfig/XrayVlessTlsConfig's own UUID regex - RFC 4122 textual form.
private val QUIC_UUID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)

// Same set REALITY/TLS_TCP already use - uTLS ClientHello fingerprinting is a
// general TLS-layer property, independent of the transport carried over it.
private val QUIC_SUPPORTED_FINGERPRINTS = setOf("chrome", "firefox", "safari", "edge")

private val QUIC_IPV4_REGEX = Regex(
    "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$",
)

// A non-blank absolute HTTP path, no query string/fragment/whitespace -
// matches what xray-core's own XHTTP `path` field accepts (see
// docs/B21_QUIC_TRANSPORT_AUDIT.md's local `-test` validation).
private val QUIC_PATH_REGEX = Regex("^/[A-Za-z0-9._~/-]*$")
