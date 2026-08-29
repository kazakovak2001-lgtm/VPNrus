package net.pocvpn.client.provisioning

/**
 * B8K4A - the outcome of one POST /v1/xray-profile attempt against the live
 * production edge. Kept separate from [ProvisioningResult] rather than
 * folded into it: the two endpoints return unrelated wire shapes (AWG
 * peer/activation fields vs. VLESS+REALITY fields), and a single closed set
 * mixing both would force every caller to handle cases that can never occur
 * for the endpoint it actually called.
 */
sealed class XrayProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val flow: String,
        val serverName: String,
        val fingerprint: String,
        val realityPublicKey: String,
        val shortId: String,
    ) : XrayProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : XrayProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : XrayProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : XrayProfileResult()

    /** HTTP 503 - the Xray profile service is temporarily unavailable. */
    object ServiceUnavailable : XrayProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : XrayProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : XrayProfileResult()
}
