package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B-WL2 - VLESS + REALITY + XHTTP client config against the pinned xray-core v26.7.28 schema. */
class XrayRealityXhttpRendererTest {

    private val reality = XrayVlessRealityConfig(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        flow = "",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
    )
    private val config = XrayVlessRealityXhttpConfig(reality, xhttpPath = "/nx7/", mode = XrayXhttpMode.AUTO)

    private fun outbound() = JSONObject(XrayConfigRenderer.render(config)).getJSONArray("outbounds").getJSONObject(0)

    @Test
    fun `stream settings use network xhttp with security reality - the combination v26_7_28 accepts`() {
        val stream = outbound().getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("reality", stream.getString("security"))
        assertFalse("never falls back to TLS settings", stream.has("tlsSettings"))
    }

    @Test
    fun `reality settings carry the same client fields as the RAW REALITY outbound`() {
        val rs = outbound().getJSONObject("streamSettings").getJSONObject("realitySettings")
        assertEquals("chrome", rs.getString("fingerprint"))
        assertEquals("www.microsoft.com", rs.getString("serverName"))
        assertEquals("A".repeat(43), rs.getString("publicKey"))
        assertEquals("ab12cd34", rs.getString("shortId"))
        assertEquals(setOf("fingerprint", "serverName", "publicKey", "shortId"), rs.keySet())
    }

    @Test
    fun `xhttp settings emit only path and mode, leaving every other field at its pinned default`() {
        val xs = outbound().getJSONObject("streamSettings").getJSONObject("xhttpSettings")
        assertEquals(setOf("path", "mode"), xs.keySet())
        assertEquals("/nx7/", xs.getString("path"))
        assertEquals("auto", xs.getString("mode"))
    }

    @Test
    fun `every supported mode renders its exact wire value`() {
        mapOf(
            XrayXhttpMode.AUTO to "auto", XrayXhttpMode.PACKET_UP to "packet-up",
            XrayXhttpMode.STREAM_UP to "stream-up", XrayXhttpMode.STREAM_ONE to "stream-one",
        ).forEach { (mode, wire) ->
            val out = JSONObject(XrayConfigRenderer.render(config.copy(mode = mode))).getJSONArray("outbounds").getJSONObject(0)
            assertEquals(wire, out.getJSONObject("streamSettings").getJSONObject("xhttpSettings").getString("mode"))
        }
    }

    @Test
    fun `the vless user never carries a flow over xhttp`() {
        val user = outbound().getJSONObject("settings").getJSONArray("vnext").getJSONObject(0).getJSONArray("users").getJSONObject(0)
        assertEquals("3fa85f64-5717-4562-b3fc-2c963f66afa6", user.getString("id"))
        assertEquals("none", user.getString("encryption"))
        assertFalse(user.has("flow"))
    }

    @Test
    fun `a valid config validates, reusing the REALITY validator for shared fields`() {
        assertTrue(validateXrayVlessRealityXhttpConfig(config) is XrayRealityXhttpConfigValidationResult.Valid)
        val bad = validateXrayVlessRealityXhttpConfig(config.copy(reality = reality.copy(realityPublicKey = "short")))
        bad as XrayRealityXhttpConfigValidationResult.Invalid
        assertEquals(listOf<XrayConfigValidationError>(XrayConfigValidationError.InvalidRealityPublicKey), bad.realityErrors)
    }

    @Test
    fun `vision flow over xhttp is rejected - fail closed, never silently dropped`() {
        val result = validateXrayVlessRealityXhttpConfig(config.copy(reality = reality.copy(flow = "xtls-rprx-vision")))
        result as XrayRealityXhttpConfigValidationResult.Invalid
        assertEquals(setOf(XrayRealityXhttpConfigValidationError.VISION_FLOW_NOT_SUPPORTED_OVER_XHTTP), result.xhttpErrors)
    }

    @Test
    fun `malformed xhttp paths are rejected`() {
        listOf("", "nx7/", "/nx7", "//nx7/", "/nx7/?a=b", "/nx#7/", "/n x/").forEach { path ->
            val result = validateXrayVlessRealityXhttpConfig(config.copy(xhttpPath = path))
            assertTrue("path '$path' must be rejected", result is XrayRealityXhttpConfigValidationResult.Invalid)
        }
    }

    @Test
    fun `toString never leaks uuid, reality public key, short id or the path`() {
        val text = config.toString()
        listOf("3fa85f64-5717-4562-b3fc-2c963f66afa6", "A".repeat(43), "ab12cd34", "/nx7/").forEach {
            assertFalse("leaked $it", text.contains(it))
        }
    }
}
