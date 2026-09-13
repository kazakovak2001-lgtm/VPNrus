package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayXhttpRendererTest {
    private fun config() = XrayVlessXhttpConfig(
        server = "edge.example.org",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        tlsServerName = "edge.example.org",
        fingerprint = "chrome",
        minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3,
        alpn = "h2",
        xhttpHost = "edge.example.org",
        xhttpPath = "/xhttp/",
        queryParameters = mapOf("z" to "+", "a" to "hello world"),
        headers = mapOf("X-Nova" to "cdn"),
        mode = XrayXhttpMode.PACKET_UP,
        uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST,
        maxEachPostBytes = 524288,
        paddingPlacement = XrayXhttpPaddingPlacement.QUERY,
        paddingMinBytes = 1,
        paddingMaxBytes = 64,
    )

    @Test
    fun `renders pinned v26_7_28 XHTTP TLS field names`() {
        val root = JSONObject(XrayConfigRenderer.render(config()))
        val outbound = root.getJSONArray("outbounds").getJSONObject(0)
        val stream = outbound.getJSONObject("streamSettings")
        assertEquals("xhttp", stream.getString("network"))
        assertEquals("tls", stream.getString("security"))
        assertFalse(stream.has("realitySettings"))

        val tls = stream.getJSONObject("tlsSettings")
        assertEquals("edge.example.org", tls.getString("serverName"))
        assertEquals("chrome", tls.getString("fingerprint"))
        assertEquals("1.3", tls.getString("minVersion"))
        assertEquals("h2", tls.getJSONArray("alpn").getString(0))
        assertFalse(tls.getBoolean("allowInsecure"))

        val xhttp = stream.getJSONObject("xhttpSettings")
        assertEquals("edge.example.org", xhttp.getString("host"))
        assertEquals("/xhttp/?a=hello%20world&z=%2B", xhttp.getString("path"))
        assertEquals("packet-up", xhttp.getString("mode"))
        assertEquals("POST", xhttp.getString("uplinkHTTPMethod"))
        assertEquals(524288, xhttp.getInt("scMaxEachPostBytes"))
        assertEquals("1-64", xhttp.getString("xPaddingBytes"))
        assertTrue(xhttp.getBoolean("xPaddingObfsMode"))
        assertEquals("query", xhttp.getString("xPaddingPlacement"))
        assertEquals("repeat-x", xhttp.getString("xPaddingMethod"))
        assertFalse(xhttp.has("extra"))
        assertFalse(xhttp.has("downloadSettings"))
    }

    @Test
    fun `renderer always emits explicit positive padding instead of inheriting core defaults`() {
        val xhttp = JSONObject(XrayConfigRenderer.render(config()))
            .getJSONArray("outbounds").getJSONObject(0)
            .getJSONObject("streamSettings").getJSONObject("xhttpSettings")
        assertTrue(xhttp.has("xPaddingBytes"))
        assertEquals("1-64", xhttp.getString("xPaddingBytes"))
        assertTrue(xhttp.getBoolean("xPaddingObfsMode"))
    }

    @Test
    fun `GET outside packet-up is rejected before render`() {
        for (mode in listOf(XrayXhttpMode.AUTO, XrayXhttpMode.STREAM_UP, XrayXhttpMode.STREAM_ONE)) {
            val result = validateXrayVlessXhttpConfig(
                config().copy(mode = mode, uplinkHttpMethod = XrayXhttpUplinkHttpMethod.GET),
            )
            assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
            assertTrue(
                (result as XrayXhttpConfigValidationResult.Invalid).errors
                    .contains(XrayXhttpConfigValidationError.INVALID_MODE_METHOD_COMBINATION),
            )
        }
    }

    @Test
    fun `uuid is redacted from toString but present in wire config`() {
        val cfg = config()
        assertFalse(cfg.toString().contains(cfg.uuid))
        assertTrue(XrayConfigRenderer.render(cfg).contains(cfg.uuid))
    }
}
