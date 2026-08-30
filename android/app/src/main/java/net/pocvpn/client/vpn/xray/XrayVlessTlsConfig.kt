package net.pocvpn.client.vpn.xray

/**
 * B8O1 - typed VLESS+TLS (no REALITY) profile for the SAME isolated Xray
 * adapter shell [XrayVlessRealityConfig] already uses - see
 * docs/B8O0_TLS_TCP_FALLBACK_AUDIT.md for the pinned xray-core v26.7.28
 * source citation this is built from (infra/conf/transport_internet.go's
 * `security: "tls"` branch, infra/conf/transport_security.go's client-side
 * `TLSConfig`). Materially SIMPLER than REALITY's credential shape: no
 * `realityPublicKey`/`shortId` key-pair material at all - just [serverName]
 * (SNI) against the gateway's own real, publicly-trusted certificate (the
 * same Let's Encrypt cert `gateway/edge/nginx-pocvpn.conf` already serves
 * the control-plane API with - see the audit's own §"already satisfied"
 * finding). Deliberately excludes anything not yet needed: no `flow`
 * (xtls-rprx-vision is a REALITY/XTLS optimization, not required here -
 * see [XrayConfigRenderer]'s own docs for why it is simply omitted), no
 * `alpn`/cert-pinning/session-resumption tuning - every xray-core TLSConfig
 * field beyond `serverName`/`fingerprint`/`allowInsecure` has a safe
 * default this adapter is content to accept unset.
 *
 * `TransportKind.TLS_TCP` is NOT registered AVAILABLE anywhere yet (see
 * TransportRegistry/VpnController - unchanged by this slice) - this type
 * exists so it CAN be rendered and unit-tested, mirroring B8K1B's own
 * "isolated adapter shell, not yet wired" precedent for REALITY.
 */
data class XrayVlessTlsConfig(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
    val mtu: Int = XrayVlessRealityConfig.DEFAULT_MTU,
    val dnsServers: List<String> = XrayVlessRealityConfig.DEFAULT_DNS_SERVERS,
    /** The TUN interface's own point-to-point address (VpnService.Builder.addAddress), not a server-side value. */
    val tunLocalAddressIpv4: String = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_ADDRESS_IPV4,
    val tunLocalPrefixLengthIpv4: Int = XrayVlessRealityConfig.DEFAULT_TUN_LOCAL_PREFIX_LENGTH_IPV4,
) {
    /** Never expose uuid - this is what any accidental log/toString call sees instead. */
    override fun toString(): String = "XrayVlessTlsConfig(" +
        "server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "serverName=$serverName, fingerprint=$fingerprint, mtu=$mtu, dnsServers=$dnsServers, " +
        "tunLocalAddressIpv4=$tunLocalAddressIpv4, tunLocalPrefixLengthIpv4=$tunLocalPrefixLengthIpv4)"
}

/**
 * One reason a candidate [XrayVlessTlsConfig] is not acceptable to render
 * or connect with - see [XrayConfigValidationError]'s own REALITY sibling
 * for why this is a closed enum, not a bare string.
 */
sealed class XrayTlsConfigValidationError {
    object BlankServer : XrayTlsConfigValidationError()
    object InvalidPort : XrayTlsConfigValidationError()
    object InvalidUuid : XrayTlsConfigValidationError()
    object BlankServerName : XrayTlsConfigValidationError()
    object UnsupportedFingerprint : XrayTlsConfigValidationError()
    object InvalidMtu : XrayTlsConfigValidationError()
    object InvalidTunLocalAddress : XrayTlsConfigValidationError()
}

sealed class XrayTlsConfigValidationResult {
    data class Valid(val config: XrayVlessTlsConfig) : XrayTlsConfigValidationResult()
    data class Invalid(val errors: List<XrayTlsConfigValidationError>) : XrayTlsConfigValidationResult()
}

/**
 * Pure validation - no I/O, no logging, safe to unit-test with only
 * in-memory values. Reuses the SAME UUID/fingerprint/MTU/tun-address rules
 * [validateXrayVlessRealityConfig] already enforces (the regexes/sets that
 * back them are private to that file, so the rules are re-declared here
 * rather than shared across a REALITY-specific file - deliberately NOT
 * refactored into a shared module in this slice, to keep REALITY's own
 * file, and its own behavior, completely untouched).
 */
fun validateXrayVlessTlsConfig(config: XrayVlessTlsConfig): XrayTlsConfigValidationResult {
    val errors = mutableListOf<XrayTlsConfigValidationError>()

    if (config.server.isBlank()) errors += XrayTlsConfigValidationError.BlankServer
    if (config.serverPort !in 1..65535) errors += XrayTlsConfigValidationError.InvalidPort
    if (!TLS_UUID_REGEX.matches(config.uuid)) errors += XrayTlsConfigValidationError.InvalidUuid
    if (config.serverName.isBlank()) errors += XrayTlsConfigValidationError.BlankServerName
    if (config.fingerprint !in TLS_SUPPORTED_FINGERPRINTS) errors += XrayTlsConfigValidationError.UnsupportedFingerprint
    if (config.mtu !in 1280..65535) errors += XrayTlsConfigValidationError.InvalidMtu
    if (!TLS_IPV4_REGEX.matches(config.tunLocalAddressIpv4)) errors += XrayTlsConfigValidationError.InvalidTunLocalAddress

    return if (errors.isEmpty()) {
        XrayTlsConfigValidationResult.Valid(config)
    } else {
        XrayTlsConfigValidationResult.Invalid(errors)
    }
}

// Same rule as XrayVlessRealityConfig's own UUID_REGEX - RFC 4122 textual form.
private val TLS_UUID_REGEX = Regex(
    "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
)

// Same set REALITY's own config uses - uTLS ClientHello fingerprinting is a
// general TLS-layer property, independent of REALITY vs plain TLS security.
private val TLS_SUPPORTED_FINGERPRINTS = setOf("chrome", "firefox", "safari", "edge")

private val TLS_IPV4_REGEX = Regex(
    "^(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$",
)
