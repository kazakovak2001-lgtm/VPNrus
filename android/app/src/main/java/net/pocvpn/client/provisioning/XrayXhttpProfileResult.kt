package net.pocvpn.client.provisioning

/**
 * B64 - the Direct/EXIT XHTTP counterpart of [XrayTlsProfileResult]: the
 * outcome of one POST /v1/xray-profile attempt with `{"transport": "xhttp"}`
 * (see gateway/api/handler.py's own B60 "xhttp" transport branch). Carries
 * ONLY the fields the server actually sends for this role - never
 * minimumTlsVersion/alpn/maxEachPostBytes/padding*, which stay B61.4's own
 * client-side constants (see [net.pocvpn.client.identity.XrayXhttpProfile]'s
 * own docs for why the server deliberately does not send them).
 */
sealed class XrayXhttpProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val xhttpHost: String,
        val xhttpPath: String,
        val mode: String,
        val uplinkHttpMethod: String,
        val fingerprint: String,
    ) : XrayXhttpProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : XrayXhttpProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : XrayXhttpProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : XrayXhttpProfileResult()

    /** HTTP 503 (including error=xray_xhttp_not_configured - the gateway has no XHTTP EXIT inbound provisioned yet). */
    object ServiceUnavailable : XrayXhttpProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : XrayXhttpProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : XrayXhttpProfileResult()
}
