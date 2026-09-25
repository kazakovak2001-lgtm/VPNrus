package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B61 - validation coverage for the Frankfurt (B60) EXIT identity's own
 * required shape: [XrayXhttpConfigValidationError.INVALID_XHTTP_HOST]/
 * [XrayXhttpConfigValidationError.INVALID_TLS_SERVER_NAME] reject a raw IPv4
 * XHTTP hostname, the path must keep its trailing slash (B57), and the
 * mode/method combination pinned by B57/B59 must be accepted while an
 * inconsistent one is rejected.
 */
class XrayVlessXhttpConfigValidationTest {

    private fun validConfig() = XrayVlessXhttpConfig(
        server = "edge.aknova.pp.ua",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        tlsServerName = "edge.aknova.pp.ua",
        fingerprint = "chrome",
        minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3,
        alpn = "h2",
        xhttpHost = "edge.aknova.pp.ua",
        xhttpPath = "/nova-xhttp/",
        queryParameters = emptyMap(),
        headers = emptyMap(),
        mode = XrayXhttpMode.PACKET_UP,
        uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST,
        maxEachPostBytes = 524_288,
        paddingPlacement = XrayXhttpPaddingPlacement.HEADER,
        paddingMinBytes = 100,
        paddingMaxBytes = 1000,
    )

    @Test
    fun `the decided Frankfurt hostname is accepted`() {
        val result = validateXrayVlessXhttpConfig(validConfig())
        assertTrue(result is XrayXhttpConfigValidationResult.Valid)
    }

    @Test
    fun `a raw IPv4 address is rejected as the XHTTP hostname`() {
        val config = validConfig().copy(server = "152.70.43.1", xhttpHost = "152.70.43.1", tlsServerName = "152.70.43.1")
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
        val errors = (result as XrayXhttpConfigValidationResult.Invalid).errors
        assertTrue(XrayXhttpConfigValidationError.INVALID_XHTTP_HOST in errors)
        assertTrue(XrayXhttpConfigValidationError.INVALID_TLS_SERVER_NAME in errors)
    }

    @Test
    fun `the loopback backend address is rejected as the XHTTP hostname`() {
        val config = validConfig().copy(server = "127.0.0.1", xhttpHost = "127.0.0.1")
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
        assertTrue(
            XrayXhttpConfigValidationError.INVALID_XHTTP_HOST in (result as XrayXhttpConfigValidationResult.Invalid).errors,
        )
    }

    @Test
    fun `a path missing its trailing slash is rejected`() {
        val config = validConfig().copy(xhttpPath = "/nova-xhttp")
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
        assertTrue(
            XrayXhttpConfigValidationError.INVALID_XHTTP_PATH in (result as XrayXhttpConfigValidationResult.Invalid).errors,
        )
    }

    @Test
    fun `packet-up plus POST uplink is a valid combination`() {
        val config = validConfig().copy(mode = XrayXhttpMode.PACKET_UP, uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST)
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Valid)
    }

    @Test
    fun `GET uplink combined with a non packet-up mode is rejected`() {
        val config = validConfig().copy(mode = XrayXhttpMode.STREAM_UP, uplinkHttpMethod = XrayXhttpUplinkHttpMethod.GET)
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
        assertTrue(
            XrayXhttpConfigValidationError.INVALID_MODE_METHOD_COMBINATION in (result as XrayXhttpConfigValidationResult.Invalid).errors,
        )
    }

    @Test
    fun `a malformed uuid is rejected`() {
        val config = validConfig().copy(uuid = "not-a-uuid")
        val result = validateXrayVlessXhttpConfig(config)
        assertTrue(result is XrayXhttpConfigValidationResult.Invalid)
        assertFalse((result as XrayXhttpConfigValidationResult.Invalid).errors.isEmpty())
    }
}
