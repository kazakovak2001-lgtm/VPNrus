package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayRealityXhttpProfile

/**
 * The outcome of one `POST /v1/xray-profile` attempt with
 * `{"transport": "reality-xhttp"}` (gateway/api/handler.py). Same status
 * vocabulary as [XrayXhttpProfileResult].
 */
sealed class XrayRealityXhttpProfileResult {

    data class Success(
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val serverName: String,
        val fingerprint: String,
        val realityPublicKey: String,
        val shortId: String,
        val xhttpPath: String,
        val mode: String,
        val uplinkHttpMethod: String,
    ) : XrayRealityXhttpProfileResult() {
        override fun toString(): String = "Success(serverAddress=$serverAddress, serverPort=$serverPort, " +
            "uuid=<redacted>, serverName=$serverName, fingerprint=$fingerprint, realityPublicKey=<redacted>, " +
            "shortId=<redacted>, xhttpPath=$xhttpPath, mode=$mode, uplinkHttpMethod=$uplinkHttpMethod)"
    }

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : XrayRealityXhttpProfileResult()

    /** HTTP 403 error=revoked. */
    object Revoked : XrayRealityXhttpProfileResult()

    /** HTTP 403 error=device_not_bound. */
    object DeviceNotBound : XrayRealityXhttpProfileResult()

    /** HTTP 503, including error=xray_reality_xhttp_not_configured (the gateway has no such inbound). */
    object ServiceUnavailable : XrayRealityXhttpProfileResult()

    /** HTTP 200/201 but the body failed structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : XrayRealityXhttpProfileResult()

    /** Connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : XrayRealityXhttpProfileResult()
}

/** A validated [XrayRealityXhttpProfileResult.Success] becomes the persistable [XrayRealityXhttpProfile]. */
fun XrayRealityXhttpProfileResult.Success.toXrayRealityXhttpProfile(): XrayRealityXhttpProfile = XrayRealityXhttpProfile(
    server = serverAddress,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
    realityPublicKey = realityPublicKey,
    shortId = shortId,
    xhttpPath = xhttpPath,
    mode = mode,
    uplinkHttpMethod = uplinkHttpMethod,
)
