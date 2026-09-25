package net.pocvpn.client.vpn.xray

/**
 * B-WL2 - VLESS + REALITY + XHTTP over TCP/443: the REALITY client fields of
 * [reality] (server/port/uuid/serverName/fingerprint/publicKey/shortId and
 * the TUN settings, validated by the existing [validateXrayVlessRealityConfig])
 * carried over Xray's XHTTP transport instead of RAW TCP.
 *
 * Verified against the pinned xray-core v26.7.28 source
 * (infra/conf/transport_internet.go): `network: "xhttp"` maps to
 * ProtocolName "splithttp", which the "reality" security branch explicitly
 * accepts ("REALITY only supports RAW, XHTTP and gRPC"); XHTTP settings are
 * read from `xhttpSettings` (SplitHTTPConfig in transport_method.go), whose
 * `mode` accepts exactly auto/packet-up/stream-up/stream-one ("" -> auto).
 *
 * Fail-closed foundation: this type is not registered with TransportRegistry,
 * not selectable by Smart Connect, and no provisioning path produces it yet.
 */
data class XrayVlessRealityXhttpConfig(
    val reality: XrayVlessRealityConfig,
    /** Normalized base path, same shape rules as the CDN XHTTP path (leading and trailing '/', no query/fragment). */
    val xhttpPath: String,
    val mode: XrayXhttpMode = XrayXhttpMode.AUTO,
) {
    override fun toString(): String = "XrayVlessRealityXhttpConfig(reality=$reality, xhttpPath=<redacted>, mode=$mode)"
}

enum class XrayRealityXhttpConfigValidationError {
    /** XTLS Vision is a RAW-TCP splice optimization; this adapter never sends it over XHTTP. */
    VISION_FLOW_NOT_SUPPORTED_OVER_XHTTP,
    INVALID_XHTTP_PATH,
}

sealed interface XrayRealityXhttpConfigValidationResult {
    data class Valid(val config: XrayVlessRealityXhttpConfig) : XrayRealityXhttpConfigValidationResult
    data class Invalid(
        val realityErrors: List<XrayConfigValidationError>,
        val xhttpErrors: Set<XrayRealityXhttpConfigValidationError>,
    ) : XrayRealityXhttpConfigValidationResult
}

fun validateXrayVlessRealityXhttpConfig(config: XrayVlessRealityXhttpConfig): XrayRealityXhttpConfigValidationResult {
    val realityErrors = when (val r = validateXrayVlessRealityConfig(config.reality)) {
        is XrayConfigValidationResult.Valid -> emptyList()
        is XrayConfigValidationResult.Invalid -> r.errors
    }
    val xhttpErrors = linkedSetOf<XrayRealityXhttpConfigValidationError>()
    if (config.reality.flow.isNotEmpty()) xhttpErrors += XrayRealityXhttpConfigValidationError.VISION_FLOW_NOT_SUPPORTED_OVER_XHTTP
    if (!isXhttpPath(config.xhttpPath)) xhttpErrors += XrayRealityXhttpConfigValidationError.INVALID_XHTTP_PATH
    return if (realityErrors.isEmpty() && xhttpErrors.isEmpty()) {
        XrayRealityXhttpConfigValidationResult.Valid(config)
    } else {
        XrayRealityXhttpConfigValidationResult.Invalid(realityErrors, xhttpErrors)
    }
}
