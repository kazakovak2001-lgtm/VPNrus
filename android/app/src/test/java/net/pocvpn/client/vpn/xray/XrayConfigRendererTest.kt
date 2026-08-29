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
}
