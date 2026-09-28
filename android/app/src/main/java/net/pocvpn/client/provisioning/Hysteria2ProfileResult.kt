package net.pocvpn.client.provisioning

/**
 * B46-4A - the outcome of one POST /v1/hysteria-profile attempt against the
 * live production edge. Mirrors [XrayProfileResult]'s own shape and
 * doc/rationale exactly - a distinct type because the two endpoints return
 * unrelated wire shapes and a merged set would force every caller to handle
 * cases that can never occur for the endpoint it actually called.
 *
 * [Success.authSecret]/[Success.obfuscationSecret] are the Hysteria2-specific
 * DATA-PLANE credential minted by the server for THIS activation/device -
 * never the activation bearer credential itself (see
 * [Hysteria2ProfileProvisioner]'s own "no raw activation credential as
 * Hysteria auth" doc). [Success.profileVersion] lets the client refuse a
 * server response shaped for a profile version it does not understand,
 * even if every individual field happens to parse.
 */
sealed class Hysteria2ProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val authSecret: String,
        val sni: String,
        val obfuscationMode: String,
        val obfuscationSecret: String?,
        val profileVersion: Int,
        val issuedAtEpochSeconds: Long?,
        val expiresAtEpochSeconds: Long?,
    ) : Hysteria2ProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : Hysteria2ProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : Hysteria2ProfileResult()

    /** HTTP 403 error=expired - a once-valid activation credential has expired. */
    object Expired : Hysteria2ProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : Hysteria2ProfileResult()

    /** HTTP 503 - the Hysteria2 profile service is temporarily unavailable. */
    object ServiceUnavailable : Hysteria2ProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : Hysteria2ProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : Hysteria2ProfileResult()
}
