package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayConfigRendererTest {

    private val config = XrayVlessRealityConfig(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
        mtu = 1420,
    )

    @Test
    fun `renders a tun inbound with protocol tun and port 0`() {
        val root = JSONObject(XrayConfigRenderer.render(config))
        val inbound = root.getJSONArray("inbounds").getJSONObject(0)

        assertEquals("tun", inbound.getString("protocol"))
        assertEquals(0, inbound.getInt("port"))
        assertEquals(1420, inbound.getJSONObject("settings").getInt("mtu"))
    }

    @Test
    fun `renders a vless outbound with the exact pinned schema field names`() {
        val root = JSONObject(XrayConfigRenderer.render(config))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("vless", outbound.getString("protocol"))
        val vnext = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals(config.server, vnext.getString("address"))
        assertEquals(config.serverPort, vnext.getInt("port"))

        val user = vnext.getJSONArray("users").getJSONObject(0)
        assertEquals(config.uuid, user.getString("id"))
        assertEquals("none", user.getString("encryption"))
        assertEquals(config.flow, user.getString("flow"))
    }

    @Test
    fun `renders reality stream settings with the exact pinned client field names`() {
        val root = JSONObject(XrayConfigRenderer.render(config))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")

        assertEquals("tcp", stream.getString("network"))
        assertEquals("reality", stream.getString("security"))

        val reality = stream.getJSONObject("realitySettings")
        assertEquals(config.fingerprint, reality.getString("fingerprint"))
        assertEquals(config.serverName, reality.getString("serverName"))
        assertEquals(config.realityPublicKey, reality.getString("publicKey"))
        assertEquals(config.shortId, reality.getString("shortId"))
    }

    @Test
    fun `rendered JSON never contains raw string concatenation artifacts for a value with special characters`() {
        // A server name/uuid containing JSON-significant characters must still
        // round-trip safely because org.json.JSONObject.put escapes them -
        // this is what "not built by unsafe string concatenation" buys.
        val tricky = config.copy(serverName = "evil\".com\",\"injected\":true,\"x\":\"")
        val root = JSONObject(XrayConfigRenderer.render(tricky))
        val reality = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("realitySettings")
        assertEquals(tricky.serverName, reality.getString("serverName"))
        assertFalse(root.has("injected"))
    }

    @Test
    fun `rendered JSON never contains the raw config toString`() {
        val rendered = XrayConfigRenderer.render(config)
        assertTrue(rendered.contains(config.uuid)) // the real credential IS expected inside the wire config
        assertFalse(rendered.contains("<redacted>")) // but never the redacted marker from toString()
    }

    // B8O1 - REALITY non-regression: this exact structure was captured from
    // XrayConfigRenderer.render(XrayVlessRealityConfig) BEFORE the B8O1
    // TLS-rendering slice touched this file (the only shared change was
    // renderTunInbound's signature, config -> mtu: Int, an internal
    // refactor that must produce structurally identical output - key
    // ORDER is never semantically meaningful in JSON, so this compares
    // structurally via JSONObject.similar(), not as a literal string). If
    // this ever fails, REALITY's own wire format changed - which this
    // slice must never do.
    @Test
    fun `REALITY rendering is structurally unchanged by the B8O1 TLS-rendering slice`() {
        val expected = JSONObject(
            "{\"log\":{\"loglevel\":\"warning\"}," +
                "\"inbounds\":[{\"tag\":\"nova-tun-in\",\"protocol\":\"tun\",\"port\":0," +
                "\"settings\":{\"name\":\"nova-xray-tun\",\"desc\":\"Nova\",\"mtu\":1420}}]," +
                "\"outbounds\":[{\"tag\":\"nova-vless-reality-out\",\"protocol\":\"vless\"," +
                "\"settings\":{\"vnext\":[{\"address\":\"vless.example.net\",\"port\":443," +
                "\"users\":[{\"id\":\"3fa85f64-5717-4562-b3fc-2c963f66afa6\",\"encryption\":\"none\"," +
                "\"flow\":\"xtls-rprx-vision\"}]}]}," +
                "\"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\"," +
                "\"realitySettings\":{\"fingerprint\":\"chrome\",\"serverName\":\"www.microsoft.com\"," +
                "\"publicKey\":\"${"A".repeat(43)}\",\"shortId\":\"ab12cd34\"}}}]}",
        )
        val actual = JSONObject(XrayConfigRenderer.render(config))
        assertTrue("expected=$expected actual=$actual", expected.similar(actual))
    }

    private val tlsConfig = XrayVlessTlsConfig(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        serverName = "vpn.example.invalid",
        fingerprint = "chrome",
        mtu = 1420,
    )

    @Test
    fun `renders a tun inbound for TLS identical in shape to REALITY's`() {
        val root = JSONObject(XrayConfigRenderer.render(tlsConfig))
        val inbound = root.getJSONArray("inbounds").getJSONObject(0)

        assertEquals("tun", inbound.getString("protocol"))
        assertEquals(0, inbound.getInt("port"))
        assertEquals(1420, inbound.getJSONObject("settings").getInt("mtu"))
    }

    @Test
    fun `renders a vless outbound for TLS with no flow key at all`() {
        val root = JSONObject(XrayConfigRenderer.render(tlsConfig))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)

        assertEquals("vless", outbound.getString("protocol"))
        val vnext = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
        assertEquals(tlsConfig.server, vnext.getString("address"))
        assertEquals(tlsConfig.serverPort, vnext.getInt("port"))

        val user = vnext.getJSONArray("users").getJSONObject(0)
        assertEquals(tlsConfig.uuid, user.getString("id"))
        assertEquals("none", user.getString("encryption"))
        assertFalse("REALITY's xtls-rprx-vision flow is not required for plain TLS", user.has("flow"))
    }

    @Test
    fun `renders TLS stream settings with security tls, tlsSettings, and no REALITY-specific keys at all`() {
        val root = JSONObject(XrayConfigRenderer.render(tlsConfig))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")

        assertEquals("tcp", stream.getString("network"))
        assertEquals("tls", stream.getString("security"))
        assertFalse(stream.has("realitySettings"))

        val tls = stream.getJSONObject("tlsSettings")
        assertEquals(tlsConfig.serverName, tls.getString("serverName"))
        assertEquals(tlsConfig.fingerprint, tls.getString("fingerprint"))
        assertFalse("allowInsecure must always be explicit false - never a bypassable field", tls.getBoolean("allowInsecure"))
    }

    @Test
    fun `TLS rendered JSON never contains raw string concatenation artifacts for a value with special characters`() {
        val tricky = tlsConfig.copy(serverName = "evil\".com\",\"injected\":true,\"x\":\"")
        val root = JSONObject(XrayConfigRenderer.render(tricky))
        val tls = root.getJSONArray("outbounds").getJSONObject(0).getJSONObject("streamSettings").getJSONObject("tlsSettings")
        assertEquals(tricky.serverName, tls.getString("serverName"))
        assertFalse(root.has("injected"))
    }
}
