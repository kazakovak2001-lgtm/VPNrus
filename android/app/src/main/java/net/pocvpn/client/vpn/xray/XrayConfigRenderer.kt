package net.pocvpn.client.vpn.xray

import org.json.JSONArray
import org.json.JSONObject

/**
 * Pure renderer: [XrayVlessRealityConfig]/[XrayVlessTlsConfig] -> the exact
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
    private const val VLESS_QUIC_OUTBOUND_TAG = "nova-vless-quic-out"
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
     * B21 - real QUIC/HTTP-3 via xray-core's XHTTP transport (`network:
     * "xhttp"`, `mode: "stream-one"`), NOT the removed standalone `"quic"`
     * network value - see docs/B21_QUIC_TRANSPORT_AUDIT.md §2-3 for the
     * pinned-source citation proving `"quic"` is a hard config-load error in
     * v26.7.28 and `xhttp`/`stream-one`/ALPN `h3` is the real, currently
     * supported replacement (empirically confirmed against the pinned
     * `xray` binary via `-test` - see the audit's §3/§6). `tlsSettings.alpn`
     * MUST include `"h3"` - this is literally what selects the real
     * quic-go/http3 client path in the pinned source
     * (transport/internet/splithttp/dialer.go's `tlsConfig.NextProtocol[0]
     * == "h3"` check) rather than an HTTP/2 XHTTP fallback. No `flow` key -
     * same reasoning as [renderVlessTlsOutbound] (XTLS-Vision is a
     * REALITY-specific optimization).
     */
    fun render(config: XrayVlessQuicConfig): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))
        root.put("inbounds", JSONArray().put(renderTunInbound(config.mtu)))
        root.put("outbounds", JSONArray().put(renderVlessQuicOutbound(config)))
        return root.toString()
    }

    /**
     * B21-fix - outbound-only config: NO inbounds at all (not even the tun
     * inbound [render] above always includes). Exists ONLY for the debug-only
     * outbound-isolation harness (see docs/B21_QUIC_TRANSPORT_AUDIT.md
     * continuation notes) that proves/disproves whether an Xray outbound can
     * dial successfully independent of Nova's VpnService/TUN routing path -
     * `startLoop(config, fd)`'s fd is meaningless here since no "tun"
     * protocol inbound ever reads it. Never used by any real connect path -
     * [render] (with its tun inbound) is what every real
     * REALITY/TLS_TCP/QUIC connect attempt actually uses.
     */
    fun renderOutboundOnly(config: XrayVlessQuicConfig): String {
        val root = JSONObject()
        // B21-fix - "info" (not the production "warning") deliberately: the
        // real underlying XHTTP/H3 dial error splithttp's DefaultDialerClient
        // .OpenStream (transport/internet/splithttp/client.go) captures is
        // only ever surfaced via errors.LogInfoInner - Info level - before
        // being masked, everywhere else, by the generic io.ErrClosedPipe a
        // WaitReadCloser read produces once OpenStream's own goroutine calls
        // wrc.Close() on failure without ever setting wrc.ReadCloser. At
        // "warning" this real cause is silently suppressed. Only this
        // debug-only isolation config raises verbosity - render()'s real
        // connect-path configs are untouched.
        root.put("log", JSONObject().put("loglevel", "info"))
        root.put("inbounds", JSONArray())
        root.put("outbounds", JSONArray().put(renderVlessQuicOutbound(config)))
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

    private fun renderVlessQuicOutbound(config: XrayVlessQuicConfig): JSONObject {
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
            .put("alpn", JSONArray().put("h3"))
            .put("allowInsecure", false)

        val xhttpSettings = JSONObject()
            .put("host", config.serverName)
            .put("path", config.path)
            .put("mode", "stream-one")

        val streamSettings = JSONObject()
            .put("network", "xhttp")
            .put("security", "tls")
            .put("tlsSettings", tlsSettings)
            .put("xhttpSettings", xhttpSettings)

        return JSONObject()
            .put("tag", VLESS_QUIC_OUTBOUND_TAG)
            .put("protocol", "vless")
            .put("settings", settings)
            .put("streamSettings", streamSettings)
    }
}
