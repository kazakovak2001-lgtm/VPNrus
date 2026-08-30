package net.pocvpn.client.provisioning

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileResult]: the outcome of one
 * POST /v1/xray-profile attempt with `{"transport": "tls"}`. Materially
 * fewer fields than REALITY's own Success (no flow/realityPublicKey/
 * shortId) - see gateway/api/handler.py's own "TLS needs fewer fields"
 * response shape.
 */
sealed class XrayTlsProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val serverName: String,
        val fingerprint: String,
    ) : XrayTlsProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : XrayTlsProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : XrayTlsProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : XrayTlsProfileResult()

    /** HTTP 503 (including error=xray_tls_not_configured - the gateway has no TLS inbound provisioned yet). */
    object ServiceUnavailable : XrayTlsProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : XrayTlsProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : XrayTlsProfileResult()
}
