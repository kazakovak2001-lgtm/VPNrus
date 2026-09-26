package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * B61 - a persistable VLESS+XHTTP (Frankfurt EXIT, B60) profile - the XHTTP
 * counterpart of [XrayTlsProfile]. Carries ONLY the fields B60's
 * `POST /v1/xray-profile` (`transport=xhttp`) actually returns
 * (server_address/server_port/uuid/xhttp_host/xhttp_path/mode/
 * uplink_http_method/fingerprint) - never a field the server does not send
 * (see gateway/api/handler.py's own B60 docs for exactly which
 * XrayVlessXhttpConfig fields are deliberately NOT sourced from the server:
 * minimumTlsVersion/alpn/queryParameters/headers/maxEachPostBytes/padding*).
 * Deliberately NOT [net.pocvpn.client.vpn.xray.CdnXhttpRuntimeConfigResolver]/
 * ingress-specific - this is the EXIT role's own, independent identity type.
 */
data class XrayXhttpProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val xhttpHost: String,
    val xhttpPath: String,
    val mode: String,
    val uplinkHttpMethod: String,
    val fingerprint: String,
) {
    /** Never expose uuid in a log or crash report. */
    override fun toString(): String = "XrayXhttpProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "xhttpHost=$xhttpHost, xhttpPath=$xhttpPath, mode=$mode, uplinkHttpMethod=$uplinkHttpMethod, " +
        "fingerprint=$fingerprint)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_XHTTP_HOST, xhttpHost)
        .put(KEY_XHTTP_PATH, xhttpPath)
        .put(KEY_MODE, mode)
        .put(KEY_UPLINK_HTTP_METHOD, uplinkHttpMethod)
        .put(KEY_FINGERPRINT, fingerprint)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_XHTTP_HOST = "xhttpHost"
        private const val KEY_XHTTP_PATH = "xhttpPath"
        private const val KEY_MODE = "mode"
        private const val KEY_UPLINK_HTTP_METHOD = "uplinkHttpMethod"
        private const val KEY_FINGERPRINT = "fingerprint"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayXhttpProfile {
            val obj = JSONObject(json)
            return XrayXhttpProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                xhttpHost = obj.getString(KEY_XHTTP_HOST),
                xhttpPath = obj.getString(KEY_XHTTP_PATH),
                mode = obj.getString(KEY_MODE),
                uplinkHttpMethod = obj.getString(KEY_UPLINK_HTTP_METHOD),
                fingerprint = obj.getString(KEY_FINGERPRINT),
            )
        }
    }
}
