package net.pocvpn.client.vpn.xray

import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

/**
 * Pure renderer: [XrayVlessRealityConfig]/[XrayVlessTlsConfig]/[XrayVlessXhttpConfig] -> the exact
 * Xray core JSON config this adapter starts CoreController.startLoop(...)
 * with. Every key name here was verified against the pinned xray-core
 * v26.7.28 source (not assumed from documentation) - see
 * docs/B8K1A_TUN_SOCKET_PATH_AUDIT.md (REALITY) / docs/B8O0_TLS_TCP_FALLBACK_AUDIT.md
 * (TLS) and this file's inline references:
 *
 * - inbound "tun": infra/conf/tun.go's Config (name/desc/mtu) and
 *   infra/conf/xray.go's InboundDetourConfig (protocol/port/tag/settings) -
 *   port is 0 for tun per proxy/tun/README.md's own documented example
 *   (InboundDetourConfig.Build() explicitly skips port validation when
 *   protocol == "tun"). Identical for both REALITY and TLS - the tun
 *   inbound has no security-mode-specific fields at all.
 * - outbound "vless": infra/conf/vless.go's VLessOutboundVnext
 *   (address/port/users) and per-user id/encryption/flow - independent of
 *   streamSettings.security (confirmed against the pinned source for
 *   B8O0 - vless.go has no reference to TLS/REALITY/security at all).
 *   [renderVlessTlsOutbound] omits `flow` entirely (unlike REALITY's
 *   `xtls-rprx-vision`) - a REALITY/XTLS-specific optimization, not
 *   required for plain TLS, and xray-core's own vless.go accepts a missing
 *   flow the same as an explicit "".
 * - streamSettings: infra/conf/transport_internet.go's StreamConfig
 *   (network/security/realitySettings|tlsSettings) with network="tcp"
 *   (REALITY requires ProtocolName == "tcp"/"splithttp"/"grpc" per
 *   transport_internet.go; this adapter only ever uses "tcp" for both).
 * - realitySettings: infra/conf/transport_security.go's client-side
 *   REALITYConfig fields (fingerprint/serverName/publicKey/shortId).
 * - tlsSettings: infra/conf/transport_security.go's client-side TLSConfig -
 *   only `serverName`/`fingerprint`/`allowInsecure` are emitted; every
 *   other TLSConfig field (alpn, cert pinning, session resumption, ...) has
 *   a safe xray-core default this adapter is content to leave unset (see
 *   XrayVlessTlsConfig's own docs). `allowInsecure` is ALWAYS emitted as
 *   `false`, explicit, never a field this adapter can set true - normal
 *   platform/system CA trust only, matching this app's existing
 *   "never pinned, never trust-all" discipline (HttpsGatewayReachabilityProbe).
 *
 * Uses org.json.JSONObject/JSONArray (this project's existing JSON tooling,
 * see ProvisioningClient) - never raw string concatenation, so a value can
 * never break out of its JSON string context.
 */
object XrayConfigRenderer {

    private const val TUN_INBOUND_TAG = "nova-tun-in"
    private const val VLESS_OUTBOUND_TAG = "nova-vless-reality-out"
    private const val VLESS_TLS_OUTBOUND_TAG = "nova-vless-tls-out"
    private const val VLESS_XHTTP_OUTBOUND_TAG = "nova-vless-xhttp-out"
    private const val VLESS_REALITY_XHTTP_OUTBOUND_TAG = "nova-vless-reality-xhttp-out"
    private const val TUN_INTERFACE_NAME = "nova-xray-tun"

    fun render(config: XrayVlessRealityConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config.mtu)))
        root.put("outbounds", JSONArray().put(renderVlessRealityOutbound(config)))
        return root.toString()
    }

    /** B8O1 - see this object's own docs for exactly what differs from [render] above. */
    fun render(config: XrayVlessTlsConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config.mtu)))
        root.put("outbounds", JSONArray().put(renderVlessTlsOutbound(config)))
        return root.toString()
    }

    /**
     * B35 renderer foundation. Registration/execution remains fail-closed
     * elsewhere until the patched core, provider deployment and data-plane
     * proof are all present.
     */
    fun render(config: XrayVlessXhttpConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config.mtu)))
        root.put("outbounds", JSONArray().put(renderVlessXhttpOutbound(config)))
        return root.toString()
    }

    /**
     * B-WL2 - VLESS + REALITY + XHTTP. Same REALITY client fields as [render]
     * for [XrayVlessRealityConfig]; `flow` is omitted (validation rejects a
     * non-empty one), and only `path`/`mode` are emitted for XHTTP so every
     * other SplitHTTPConfig field keeps its v26.7.28 default (padding
     * 100..1000, POST uplink, path session/seq placement). The HTTP Host is
     * left to Xray's own client priority (host > serverName > address), i.e.
     * the REALITY serverName.
     */
    fun render(config: XrayVlessRealityXhttpConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config.reality.mtu)))
        root.put("outbounds", JSONArray().put(renderVlessRealityXhttpOutbound(config)))
        return root.toString()
    }

    private fun renderTunInbound(mtu: Int): JSONObject {
        val settings = JSONObject()
            .put("name", TUN_INTERFACE_NAME)
            .put("desc", "Nova")
            .put("mtu", mtu)

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

    private fun renderVlessRealityXhttpOutbound(config: XrayVlessRealityXhttpConfig): JSONObject {
        val reality = config.reality
        val user = JSONObject()
            .put("id", reality.uuid)
            .put("encryption", "none")

        val vnext = JSONObject()
            .put("address", reality.server)
            .put("port", reality.serverPort)
            .put("users", JSONArray().put(user))

        val realitySettings = JSONObject()
            .put("fingerprint", reality.fingerprint)
            .put("serverName", reality.serverName)
            .put("publicKey", reality.realityPublicKey)
            .put("shortId", reality.shortId)

        val xhttpSettings = JSONObject()
            .put("path", config.xhttpPath)
            .put("mode", config.mode.wireValue)

        val streamSettings = JSONObject()
            .put("network", "xhttp")
            .put("security", "reality")
            .put("realitySettings", realitySettings)
            .put("xhttpSettings", xhttpSettings)

        return JSONObject()
            .put("tag", VLESS_REALITY_XHTTP_OUTBOUND_TAG)
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
            .put("streamSettings", streamSettings)
    }

    private fun renderVlessTlsOutbound(config: XrayVlessTlsConfig): JSONObject {
        val user = JSONObject()
            .put("id", config.uuid)
            .put("encryption", "none")

        val vnext = JSONObject()
            .put("address", config.server)
            .put("port", config.serverPort)
            .put("users", JSONArray().put(user))

        val settings = JSONObject().put("vnext", JSONArray().put(vnext))

        val tlsSettings = JSONObject()
            .put("serverName", config.serverName)
            .put("fingerprint", config.fingerprint)
            .put("allowInsecure", false)

        val streamSettings = JSONObject()
            .put("network", "tcp")
            .put("security", "tls")
            .put("tlsSettings", tlsSettings)

        return JSONObject()
            .put("tag", VLESS_TLS_OUTBOUND_TAG)
            .put("protocol", "vless")
            .put("settings", settings)
            .put("streamSettings", streamSettings)
    }

    private fun renderVlessXhttpOutbound(config: XrayVlessXhttpConfig): JSONObject {
        val user = JSONObject()
            .put("id", config.uuid)
            .put("encryption", "none")

        val vnext = JSONObject()
            .put("address", config.server)
            .put("port", config.serverPort)
            .put("users", JSONArray().put(user))

        val tlsSettings = JSONObject()
            .put("serverName", config.tlsServerName)
            .put("fingerprint", config.fingerprint)
            .put("minVersion", config.minimumTlsVersion.wireValue)
            .put("alpn", JSONArray().put(config.alpn))
            .put("allowInsecure", false)

        val xhttpSettings = JSONObject()
            .put("host", config.xhttpHost)
            .put("path", renderXhttpPathAndQuery(config))
            .put("mode", config.mode.wireValue)
            .put("uplinkHTTPMethod", config.uplinkHttpMethod.wireValue)
            .put("scMaxEachPostBytes", config.maxEachPostBytes)
            .put("headers", JSONObject().apply {
                    config.headers.toSortedMap().forEach { (key, value) ->
                        put(key, value)
                    }
                })

        // Always explicit. v26.7.28 treats omitted/zero xPaddingBytes as
        // its own 100..1000 default, so omission could never mean "NONE".
        xhttpSettings
            .put("xPaddingBytes", renderXhttpRange(config.paddingMinBytes, config.paddingMaxBytes))
            .put("xPaddingObfsMode", true)
            .put("xPaddingPlacement", config.paddingPlacement.wireValue)
            .put("xPaddingMethod", "repeat-x")

        val streamSettings = JSONObject()
            .put("network", "xhttp")
            .put("security", "tls")
            .put("tlsSettings", tlsSettings)
            .put("xhttpSettings", xhttpSettings)

        return JSONObject()
            .put("tag", VLESS_XHTTP_OUTBOUND_TAG)
            .put("protocol", "vless")
            .put("settings", JSONObject().put("vnext", JSONArray().put(vnext)))
            .put("streamSettings", streamSettings)
    }

    private fun renderXhttpPathAndQuery(config: XrayVlessXhttpConfig): String {
        if (config.queryParameters.isEmpty()) return config.xhttpPath
        val query = config.queryParameters.toSortedMap().entries.joinToString("&") { (key, value) ->
            "${encodeXhttpQueryComponent(key)}=${encodeXhttpQueryComponent(value)}"
        }
        return "${config.xhttpPath}?$query"
    }

    private fun encodeXhttpQueryComponent(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8.name()).replace("+", "%20")

    private fun renderXhttpRange(from: Int, to: Int): Any =
        if (from == to) from else "$from-$to"
}
