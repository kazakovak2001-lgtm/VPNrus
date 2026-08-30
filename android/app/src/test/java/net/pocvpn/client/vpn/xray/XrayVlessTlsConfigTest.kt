package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private fun validTlsConfig(
    server: String = "vless.example.net",
    serverPort: Int = 443,
    uuid: String = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    serverName: String = "vpn.example.invalid",
    fingerprint: String = "chrome",
) = XrayVlessTlsConfig(
    server = server,
    serverPort = serverPort,
    uuid = uuid,
    serverName = serverName,
    fingerprint = fingerprint,
)

class XrayVlessTlsConfigTest {

    @Test
    fun `a fully valid config passes validation`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig())
        assertTrue(result is XrayTlsConfigValidationResult.Valid)
    }

    @Test
    fun `malformed UUID is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(uuid = "not-a-uuid"))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.InvalidUuid))
    }

    @Test
    fun `port 0 is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(serverPort = 0))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.InvalidPort))
    }

    @Test
    fun `port above 65535 is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(serverPort = 70000))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.InvalidPort))
    }

    @Test
    fun `blank server is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(server = "  "))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.BlankServer))
    }

    @Test
    fun `blank server name (SNI) is rejected - it is the one field a correct TLS config cannot omit`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(serverName = ""))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.BlankServerName))
    }

    @Test
    fun `unsupported fingerprint is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig(fingerprint = "made-up-browser"))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.UnsupportedFingerprint))
    }

    @Test
    fun `out-of-range mtu is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig().copy(mtu = 100))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.InvalidMtu))
    }

    @Test
    fun `invalid tun local address is rejected`() {
        val result = validateXrayVlessTlsConfig(validTlsConfig().copy(tunLocalAddressIpv4 = "not-an-ip"))
        assertTrue((result as XrayTlsConfigValidationResult.Invalid).errors.contains(XrayTlsConfigValidationError.InvalidTunLocalAddress))
    }

    @Test
    fun `toString never contains the raw uuid`() {
        val config = validTlsConfig(uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6")
        val rendered = config.toString()
        assertFalse(rendered.contains(config.uuid))
        assertTrue(rendered.contains("<redacted>"))
    }

    @Test
    fun `has no realityPublicKey or shortId field at all - materially simpler credential shape than REALITY`() {
        val fieldNames = XrayVlessTlsConfig::class.java.declaredFields.map { it.name }.filterNot { it.contains('$') }
        assertFalse(fieldNames.contains("realityPublicKey"))
        assertFalse(fieldNames.contains("shortId"))
        assertFalse(fieldNames.contains("flow"))
    }
}
