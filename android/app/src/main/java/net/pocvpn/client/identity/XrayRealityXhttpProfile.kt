package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * A persistable VLESS over XHTTP secured by REALITY profile - what
 * `POST /v1/xray-profile` with `transport=reality-xhttp` returns
 * (gateway/api/handler.py): the REALITY client fields of [XrayProfile]
 * without `flow` (XTLS Vision is not valid over XHTTP) plus the XHTTP path,
 * mode and uplink method of [XrayXhttpProfile]. No xhttp host: REALITY
 * dials the gateway address directly and presents [serverName].
 */
data class XrayRealityXhttpProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
    val realityPublicKey: String,
    val shortId: String,
    val xhttpPath: String,
    val mode: String,
    val uplinkHttpMethod: String,
) {
    /** Never expose uuid, the REALITY public key or the short id in a log or crash report. */
    override fun toString(): String = "XrayRealityXhttpProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "serverName=$serverName, fingerprint=$fingerprint, realityPublicKey=<redacted>, shortId=<redacted>, " +
        "xhttpPath=$xhttpPath, mode=$mode, uplinkHttpMethod=$uplinkHttpMethod)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_SERVER_NAME, serverName)
        .put(KEY_FINGERPRINT, fingerprint)
        .put(KEY_REALITY_PUBLIC_KEY, realityPublicKey)
        .put(KEY_SHORT_ID, shortId)
        .put(KEY_XHTTP_PATH, xhttpPath)
        .put(KEY_MODE, mode)
        .put(KEY_UPLINK_HTTP_METHOD, uplinkHttpMethod)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_SERVER_NAME = "serverName"
        private const val KEY_FINGERPRINT = "fingerprint"
        private const val KEY_REALITY_PUBLIC_KEY = "realityPublicKey"
        private const val KEY_SHORT_ID = "shortId"
        private const val KEY_XHTTP_PATH = "xhttpPath"
        private const val KEY_MODE = "mode"
        private const val KEY_UPLINK_HTTP_METHOD = "uplinkHttpMethod"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayRealityXhttpProfile {
            val obj = JSONObject(json)
            return XrayRealityXhttpProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                serverName = obj.getString(KEY_SERVER_NAME),
                fingerprint = obj.getString(KEY_FINGERPRINT),
                realityPublicKey = obj.getString(KEY_REALITY_PUBLIC_KEY),
                shortId = obj.getString(KEY_SHORT_ID),
                xhttpPath = obj.getString(KEY_XHTTP_PATH),
                mode = obj.getString(KEY_MODE),
                uplinkHttpMethod = obj.getString(KEY_UPLINK_HTTP_METHOD),
            )
        }
    }
}
