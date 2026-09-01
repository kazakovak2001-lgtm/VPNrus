package net.pocvpn.client.provisioning

/**
 * B21 - the QUIC counterpart of [XrayTlsProfileResult]: the outcome of one
 * POST /v1/xray-profile attempt with `{"transport": "quic"}`. Same
 * TLS-style field set plus [Success.path] - see
 * docs/B21_QUIC_TRANSPORT_AUDIT.md §5 for why no REALITY-only field
 * (flow/reality_public_key/short_id) applies here.
 */
sealed class XrayQuicProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val serverName: String,
        val fingerprint: String,
        val path: String,
    ) : XrayQuicProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : XrayQuicProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : XrayQuicProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : XrayQuicProfileResult()

    /** HTTP 503 (including error=xray_quic_not_configured - the gateway has no QUIC inbound provisioned yet). */
    object ServiceUnavailable : XrayQuicProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : XrayQuicProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : XrayQuicProfileResult()
}
