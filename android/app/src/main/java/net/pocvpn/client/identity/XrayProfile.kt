package net.pocvpn.client.identity

import org.json.JSONObject

/**
 * B8K1B - a persistable VLESS+REALITY profile. Same fields as
 * net.pocvpn.client.vpn.xray.XrayVlessRealityConfig (see
 * XrayProfileMapper for the conversion) but kept as its own type here so
 * this storage-layer package stays protocol-agnostic, the same separation
 * ClientIdentity/PersistedIdentity already use for the AWG keypair.
 *
 * No real profile is ever created by this B8K1B slice - see
 * XrayProfileRepository's own docs. This type exists only so a future real
 * provisioning flow has somewhere truthful to write to.
 */
data class XrayProfile(
    val server: String,
    val serverPort: Int,
    val uuid: String,
    val flow: String,
    val serverName: String,
    val fingerprint: String,
    val realityPublicKey: String,
    val shortId: String,
) {
    /** Never expose uuid/realityPublicKey/shortId in a log or crash report. */
    override fun toString(): String = "XrayProfile(server=$server, serverPort=$serverPort, uuid=<redacted>, " +
        "flow=$flow, serverName=$serverName, fingerprint=$fingerprint, realityPublicKey=<redacted>, shortId=<redacted>)"

    fun toJson(): String = JSONObject()
        .put(KEY_SERVER, server)
        .put(KEY_SERVER_PORT, serverPort)
        .put(KEY_UUID, uuid)
        .put(KEY_FLOW, flow)
        .put(KEY_SERVER_NAME, serverName)
        .put(KEY_FINGERPRINT, fingerprint)
        .put(KEY_REALITY_PUBLIC_KEY, realityPublicKey)
        .put(KEY_SHORT_ID, shortId)
        .toString()

    companion object {
        private const val KEY_SERVER = "server"
        private const val KEY_SERVER_PORT = "serverPort"
        private const val KEY_UUID = "uuid"
        private const val KEY_FLOW = "flow"
        private const val KEY_SERVER_NAME = "serverName"
        private const val KEY_FINGERPRINT = "fingerprint"
        private const val KEY_REALITY_PUBLIC_KEY = "realityPublicKey"
        private const val KEY_SHORT_ID = "shortId"

        /** @throws org.json.JSONException on malformed/corrupted stored JSON. */
        fun fromJson(json: String): XrayProfile {
            val obj = JSONObject(json)
            return XrayProfile(
                server = obj.getString(KEY_SERVER),
                serverPort = obj.getInt(KEY_SERVER_PORT),
                uuid = obj.getString(KEY_UUID),
                flow = obj.optString(KEY_FLOW, ""),
                serverName = obj.getString(KEY_SERVER_NAME),
                fingerprint = obj.getString(KEY_FINGERPRINT),
                realityPublicKey = obj.getString(KEY_REALITY_PUBLIC_KEY),
                shortId = obj.getString(KEY_SHORT_ID),
            )
        }
    }
}
