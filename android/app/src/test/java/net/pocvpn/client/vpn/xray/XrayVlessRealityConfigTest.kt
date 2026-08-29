package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private fun validConfig(
    server: String = "vless.example.net",
    serverPort: Int = 443,
    uuid: String = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    flow: String = "xtls-rprx-vision",
    serverName: String = "www.microsoft.com",
    fingerprint: String = "chrome",
    realityPublicKey: String = "A".repeat(43),
    shortId: String = "ab12cd34",
) = XrayVlessRealityConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    flow = flow,
    serverName = serverName,
    fingerprint = fingerprint,
    realityPublicKey = realityPublicKey,
    shortId = shortId,
)

class XrayVlessRealityConfigTest {

    @Test
    fun `a fully valid config passes validation`() {
        val result = validateXrayVlessRealityConfig(validConfig())
        assertTrue(result is XrayConfigValidationResult.Valid)
    }

    @Test
    fun `malformed UUID is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(uuid = "not-a-uuid"))
        assertTrue(result is XrayConfigValidationResult.Invalid)
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidUuid))
    }

    @Test
    fun `port 0 is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(serverPort = 0))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidPort))
    }

    @Test
    fun `port above 65535 is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(serverPort = 70000))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidPort))
    }

    @Test
    fun `blank server is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(server = "  "))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.BlankServer))
    }

    @Test
    fun `blank server name is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(serverName = ""))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.BlankServerName))
    }

    @Test
    fun `blank REALITY public key is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(realityPublicKey = ""))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidRealityPublicKey))
    }

    @Test
    fun `wrong-length REALITY public key is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(realityPublicKey = "tooshort"))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidRealityPublicKey))
    }

    @Test
    fun `blank short id is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(shortId = ""))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidShortId))
    }

    @Test
    fun `odd-length short id is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(shortId = "abc"))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidShortId))
    }

    @Test
    fun `non-hex short id is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(shortId = "zzzz"))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.InvalidShortId))
    }

    @Test
    fun `unsupported flow is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(flow = "made-up-flow"))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.UnsupportedFlow))
    }

    @Test
    fun `empty flow is accepted`() {
        val result = validateXrayVlessRealityConfig(validConfig(flow = ""))
        assertTrue(result is XrayConfigValidationResult.Valid)
    }

    @Test
    fun `unsupported fingerprint is rejected`() {
        val result = validateXrayVlessRealityConfig(validConfig(fingerprint = "made-up-browser"))
        assertTrue((result as XrayConfigValidationResult.Invalid).errors.contains(XrayConfigValidationError.UnsupportedFingerprint))
    }

    @Test
    fun `toString never contains the raw uuid, reality public key, or short id`() {
        val config = validConfig(uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6", realityPublicKey = "A".repeat(43), shortId = "ab12cd34")
        val rendered = config.toString()
        assertFalse(rendered.contains(config.uuid))
        assertFalse(rendered.contains(config.realityPublicKey))
        assertFalse(rendered.contains(config.shortId))
        assertTrue(rendered.contains("<redacted>"))
    }
}
