package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B21 - proves the real QUIC/XHTTP(H3) client config shape - see
 * docs/B21_QUIC_TRANSPORT_AUDIT.md for the pinned xray-core v26.7.28 source
 * citation and local `xray run -test` validation this mirrors exactly.
 */
class XrayVlessQuicConfigTest {

    private fun validConfig() = XrayVlessQuicConfig(
        server = "203.0.113.1",
        serverPort = 443,
        uuid = "3f7c9a6e-1b2d-4e5f-9a0b-1c2d3e4f5a6b",
        serverName = "example.invalid",
        fingerprint = "chrome",
        path = "/nova-quic",
    )

    @Test
    fun `a well-formed config validates`() {
        val result = validateXrayVlessQuicConfig(validConfig())
        assertTrue(result is XrayQuicConfigValidationResult.Valid)
    }

    @Test
    fun `a non-absolute path is rejected`() {
        val result = validateXrayVlessQuicConfig(validConfig().copy(path = "nova-quic"))
        assertTrue(result is XrayQuicConfigValidationResult.Invalid)
        assertTrue((result as XrayQuicConfigValidationResult.Invalid).errors.contains(XrayQuicConfigValidationError.InvalidPath))
    }

    @Test
    fun `a malformed uuid is rejected`() {
        val result = validateXrayVlessQuicConfig(validConfig().copy(uuid = "not-a-uuid"))
        assertTrue(result is XrayQuicConfigValidationResult.Invalid)
        assertTrue((result as XrayQuicConfigValidationResult.Invalid).errors.contains(XrayQuicConfigValidationError.InvalidUuid))
    }

    @Test
    fun `toString never exposes the uuid`() {
        assertTrue(!validConfig().toString().contains("3f7c9a6e"))
    }

    @Test
    fun `rendered config uses real XHTTP stream-one with ALPN h3, never the removed standalone quic network`() {
        val rendered = JSONObject(XrayConfigRenderer.render(validConfig()))
        val outbound = rendered.getJSONArray("outbounds").getJSONObject(0)
        val streamSettings = outbound.getJSONObject("streamSettings")

        // The exact, non-removed network value - see docs/B21_QUIC_TRANSPORT_AUDIT.md §2.
        assertEquals("xhttp", streamSettings.getString("network"))
        assertTrue(streamSettings.getString("network") != "quic")
        assertEquals("tls", streamSettings.getString("security"))

        val tlsSettings = streamSettings.getJSONObject("tlsSettings")
        assertEquals("h3", tlsSettings.getJSONArray("alpn").getString(0))
        assertEquals(false, tlsSettings.getBoolean("allowInsecure"))
        assertEquals("example.invalid", tlsSettings.getString("serverName"))

        val xhttpSettings = streamSettings.getJSONObject("xhttpSettings")
        assertEquals("stream-one", xhttpSettings.getString("mode"))
        assertEquals("/nova-quic", xhttpSettings.getString("path"))

        // Same VLESS UUID identity model as REALITY/TLS_TCP - no flow key (XTLS-specific, not applicable here).
        val user = outbound.getJSONObject("settings").getJSONArray("vnext").getJSONObject(0)
            .getJSONArray("users").getJSONObject(0)
        assertEquals("3f7c9a6e-1b2d-4e5f-9a0b-1c2d3e4f5a6b", user.getString("id"))
        assertTrue(!user.has("flow"))

        // Same tun inbound every other security mode renders - no TUN-side change for QUIC.
        val inbound = rendered.getJSONArray("inbounds").getJSONObject(0)
        assertEquals("tun", inbound.getString("protocol"))
    }

    @Test
    fun `rendered config never contains the uuid outside the users array`() {
        val rendered = XrayConfigRenderer.render(validConfig())
        // sanity: uuid appears exactly once (in settings.vnext[0].users[0].id)
        val occurrences = Regex(Regex.escape("3f7c9a6e-1b2d-4e5f-9a0b-1c2d3e4f5a6b")).findAll(rendered).count()
        assertEquals(1, occurrences)
    }
}
