package net.pocvpn.client.vpn.xray

import org.json.JSONArray
import org.json.JSONObject

/**
 * Pure renderer: [XrayVlessRealityConfig] -> the exact Xray core JSON config
 * this adapter starts CoreController.startLoop(...) with. Every key name here
 * was verified against the pinned xray-core v26.7.28 source (not assumed
 * from documentation) - see docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md and this
 * file's inline references:
 *
 * - inbound "tun": infra/conf/tun.go's Config (name/desc/mtu) and
 *   infra/conf/xray.go's InboundDetourConfig (protocol/port/tag/settings) -
 *   port is 0 for tun per proxy/tun/README.md's own documented example
 *   (InboundDetourConfig.Build() explicitly skips port validation when
 *   protocol == "tun").
 * - outbound "vless": infra/conf/vless.go's VLessOutboundVnext
 *   (address/port/users) and per-user id/encryption/flow.
 * - streamSettings: infra/conf/transport_internet.go's StreamConfig
 *   (network/security/realitySettings) with network="tcp" (REALITY requires
 *   ProtocolName == "tcp"/"splithttp"/"grpc" per transport_internet.go;
 *   this adapter only ever uses "tcp").
 * - realitySettings: infra/conf/transport_security.go's client-side
 *   REALITYConfig fields (fingerprint/serverName/publicKey/shortId).
 *
 * Uses org.json.JSONObject/JSONArray (this project's existing JSON tooling,
 * see ProvisioningClient) - never raw string concatenation, so a value can
 * never break out of its JSON string context.
 */
object XrayConfigRenderer {

    private const val TUN_INBOUND_TAG = "nova-tun-in"
    private const val VLESS_OUTBOUND_TAG = "nova-vless-reality-out"
    private const val TUN_INTERFACE_NAME = "nova-xray-tun"

    fun render(config: XrayVlessRealityConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config)))
        root.put("outbounds", JSONArray().put(renderVlessRealityOutbound(config)))
        return root.toString()
    }

    private fun renderTunInbound(config: XrayVlessRealityConfig): JSONObject {
        val settings = JSONObject()
            .put("name", TUN_INTERFACE_NAME)
            .put("desc", "Nova")
            .put("mtu", config.mtu)

        return JSONObject()
            .put("tag", TUN_INBOUND_TAG)
            .put("protocol", "tun")
            .put("port", 0)
            .put("settings", settings)
    }

    private fun renderVlessRealityOutbound(config: XrayVlessRealityConfig): JSONObject {
        val user = JSONObject()
            .put("id", config.uuid)
            .put("encryption", "none")
            .put("flow", config.flow)

        val vnext = JSONObject()
            .put("address", config.server)
            .put("port", config.serverPort)
            .put("users", JSONArray().put(user))

        val settings = JSONObject().put("vnext", JSONArray().put(vnext))

        val realitySettings = JSONObject()
            .put("fingerprint", config.fingerprint)
            .put("serverName", config.serverName)
            .put("publicKey", config.realityPublicKey)
            .put("shortId", config.shortId)

        val streamSettings = JSONObject()
            .put("network", "tcp")
            .put("security", "reality")
            .put("realitySettings", realitySettings)

        return JSONObject()
            .put("tag", VLESS_OUTBOUND_TAG)
            .put("protocol", "vless")
            .put("settings", settings)
            .put("streamSettings", streamSettings)
    }
}
