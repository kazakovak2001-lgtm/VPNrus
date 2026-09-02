package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * B21 - a persistable VLESS+XHTTP(H3/QUIC) profile, the QUIC counterpart of
 * [XrayTlsProfile]. Same TLS-style credential shape (no REALITY key
 * material - see docs/B21_QUIC_TRANSPORT_AUDIT.md §5 for why REALITY does
 * not apply to a genuine QUIC/H3 transport) plus [path], the XHTTP request
 * path this gateway's inbound is configured to accept - not hardcoded,
 * server-issued like every other field here.
 */
data class XrayQuicProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val serverName: String,
    val fingerprint: String,
    val path: String,
) {
    /** Never expose uuid in a log or crash report. */
    override fun toString(): String = "XrayQuicProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "serverName=$serverName, fingerprint=$fingerprint, path=$path)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_SERVER_NAME, serverName)
        .put(KEY_FINGERPRINT, fingerprint)
        .put(KEY_PATH, path)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_SERVER_NAME = "serverName"
        private const val KEY_FINGERPRINT = "fingerprint"
        private const val KEY_PATH = "path"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayQuicProfile {
            val obj = JSONObject(json)
            return XrayQuicProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                serverName = obj.getString(KEY_SERVER_NAME),
                fingerprint = obj.getString(KEY_FINGERPRINT),
                path = obj.getString(KEY_PATH),
            )
        }
    }
}
