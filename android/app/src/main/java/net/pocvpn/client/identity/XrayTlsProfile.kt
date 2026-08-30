package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * B8O2 - a persistable VLESS+TLS (no REALITY) profile, the TLS/TCP
 * counterpart of [XrayProfile]. Materially simpler credential shape than
 * REALITY's (no flow/realityPublicKey/shortId) - see
 * net.pocvpn.client.vpn.xray.XrayVlessTlsConfig's own docs for why.
 */
data class XrayTlsProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
) {
    /** Never expose uuid in a log or crash report. */
    override fun toString(): String = "XrayTlsProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "serverName=$serverName, fingerprint=$fingerprint)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_SERVER_NAME, serverName)
        .put(KEY_FINGERPRINT, fingerprint)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_SERVER_NAME = "serverName"
        private const val KEY_FINGERPRINT = "fingerprint"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayTlsProfile {
            val obj = JSONObject(json)
            return XrayTlsProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                serverName = obj.getString(KEY_SERVER_NAME),
                fingerprint = obj.getString(KEY_FINGERPRINT),
            )
        }
    }
}
