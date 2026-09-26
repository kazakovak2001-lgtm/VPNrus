package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * B66.17 - a persistable Direct VLESS+XHTTP profile: the client identity
 * counterpart of [net.pocvpn.client.vpn.xray.XrayVlessXhttpConfig], kept as
 * its own type here so this storage-layer package stays protocol-agnostic -
 * the same separation [XrayProfile]/[XrayTlsProfile] already use. Describes
 * the EXIT gateway's own XHTTP listener directly (server/serverPort are the
 * EXIT itself) - never a CDN/ingress binding, which is a materially
 * different concept ([net.pocvpn.client.relay.IngressClientProfile]) this
 * type must never be confused with.
 */
data class XrayXhttpProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val tlsServerName: String,
    val fingerprint: String,
    val minimumTlsVersion: String,
    val alpn: String,
    val xhttpHost: String,
    val xhttpPath: String,
    val queryParameters: Map<String, String> = emptyMap(),
    val headers: Map<String, String> = emptyMap(),
    val mode: String,
    val uplinkHttpMethod: String,
    val maxEachPostBytes: Int,
    val paddingPlacement: String,
    val paddingMinBytes: Int,
    val paddingMaxBytes: Int,
) {
    /** Never expose uuid in a log or crash report. */
    override fun toString(): String = "XrayXhttpProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "tlsServerName=$tlsServerName, fingerprint=$fingerprint, minimumTlsVersion=$minimumTlsVersion, " +
        "alpn=$alpn, xhttpHost=$xhttpHost, xhttpPath=$xhttpPath, " +
        "queryParameterCount=${queryParameters.size}, headerCount=${headers.size}, " +
        "mode=$mode, uplinkHttpMethod=$uplinkHttpMethod, maxEachPostBytes=$maxEachPostBytes, " +
        "paddingPlacement=$paddingPlacement, paddingMinBytes=$paddingMinBytes, paddingMaxBytes=$paddingMaxBytes)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_TLS_SERVER_NAME, tlsServerName)
        .put(KEY_FINGERPRINT, fingerprint)
        .put(KEY_MIN_TLS_VERSION, minimumTlsVersion)
        .put(KEY_ALPN, alpn)
        .put(KEY_XHTTP_HOST, xhttpHost)
        .put(KEY_XHTTP_PATH, xhttpPath)
        .put(KEY_QUERY_PARAMETERS, mapToJson(queryParameters))
        .put(KEY_HEADERS, mapToJson(headers))
        .put(KEY_MODE, mode)
        .put(KEY_UPLINK_HTTP_METHOD, uplinkHttpMethod)
        .put(KEY_MAX_EACH_POST_BYTES, maxEachPostBytes)
        .put(KEY_PADDING_PLACEMENT, paddingPlacement)
        .put(KEY_PADDING_MIN_BYTES, paddingMinBytes)
        .put(KEY_PADDING_MAX_BYTES, paddingMaxBytes)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_TLS_SERVER_NAME = "tlsServerName"
        private const val KEY_FINGERPRINT = "fingerprint"
        private const val KEY_MIN_TLS_VERSION = "minimumTlsVersion"
        private const val KEY_ALPN = "alpn"
        private const val KEY_XHTTP_HOST = "xhttpHost"
        private const val KEY_XHTTP_PATH = "xhttpPath"
        private const val KEY_QUERY_PARAMETERS = "queryParameters"
        private const val KEY_HEADERS = "headers"
        private const val KEY_MODE = "mode"
        private const val KEY_UPLINK_HTTP_METHOD = "uplinkHttpMethod"
        private const val KEY_MAX_EACH_POST_BYTES = "maxEachPostBytes"
        private const val KEY_PADDING_PLACEMENT = "paddingPlacement"
        private const val KEY_PADDING_MIN_BYTES = "paddingMinBytes"
        private const val KEY_PADDING_MAX_BYTES = "paddingMaxBytes"

        private fun mapToJson(map: Map<String, String>): JSONObject =
            JSONObject().apply { map.forEach { (k, v) -> put(k, v) } }

        private fun jsonToMap(obj: JSONObject?): Map<String, String> {
            if (obj == null) return emptyMap()
            val out = LinkedHashMap<String, String>()
            val keys = obj.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                out[key] = obj.getString(key)
            }
            return out
        }

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayXhttpProfile {
            val obj = JSONObject(json)
            return XrayXhttpProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                tlsServerName = obj.getString(KEY_TLS_SERVER_NAME),
                fingerprint = obj.getString(KEY_FINGERPRINT),
                minimumTlsVersion = obj.getString(KEY_MIN_TLS_VERSION),
                alpn = obj.getString(KEY_ALPN),
                xhttpHost = obj.getString(KEY_XHTTP_HOST),
                xhttpPath = obj.getString(KEY_XHTTP_PATH),
                queryParameters = jsonToMap(obj.optJSONObject(KEY_QUERY_PARAMETERS)),
                headers = jsonToMap(obj.optJSONObject(KEY_HEADERS)),
                mode = obj.getString(KEY_MODE),
                uplinkHttpMethod = obj.getString(KEY_UPLINK_HTTP_METHOD),
                maxEachPostBytes = obj.getInt(KEY_MAX_EACH_POST_BYTES),
                paddingPlacement = obj.getString(KEY_PADDING_PLACEMENT),
                paddingMinBytes = obj.getInt(KEY_PADDING_MIN_BYTES),
                paddingMaxBytes = obj.getInt(KEY_PADDING_MAX_BYTES),
            )
        }
    }
}
