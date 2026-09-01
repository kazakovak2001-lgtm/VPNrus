package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B22 - proves malformed private gateway input fails closed on every field
 * (architecture "SECURITY / VALIDATION" requirement) and that a genuinely
 * valid config maps into the EXISTING [GatewayConfigSnapshot] pipeline
 * correctly (test list item 5).
 */
class PrivateGatewayConfigValidatorTest {

    private val validHeaders = AwgProfile(
        initPacketMagicHeader = "1106684696",
        responsePacketMagicHeader = "3677857287",
        underloadPacketMagicHeader = "353316806",
        transportPacketMagicHeader = "2068198996",
    )

    private fun validate(
        host: String = "203.0.113.5",
        port: Int = 51820,
        serverPublicKeyBase64: String = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp: String = "10.13.13.2",
        gatewayTunnelIp: String = "10.13.13.1",
        awgProfile: AwgProfile = validHeaders,
    ) = PrivateGatewayConfigValidator.validate(host, port, serverPublicKeyBase64, clientTunnelIp, gatewayTunnelIp, awgProfile)

    @Test
    fun `a fully valid config is accepted and maps every field through unchanged`() {
        val result = validate()

        assertTrue(result is PrivateGatewayValidationResult.Valid)
        val config = (result as PrivateGatewayValidationResult.Valid).config
        assertEquals("203.0.113.5", config.host)
        assertEquals(51820, config.port)
        assertEquals("hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=", config.serverPublicKeyBase64)
        assertEquals("10.13.13.2", config.clientTunnelIp)
        assertEquals("10.13.13.1", config.gatewayTunnelIp)
        assertEquals(PrivateGatewayConfig.ID, config.id)
    }

    @Test
    fun `a valid hostname (not just an IP) is accepted for host`() {
        val result = validate(host = "my-vps.example.com")
        assertTrue(result is PrivateGatewayValidationResult.Valid)
    }

    @Test
    fun `blank host is rejected`() {
        val result = validate(host = "   ")
        assertEquals(PrivateGatewayConfigFailureReason.BLANK_HOST, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `a host with invalid syntax is rejected`() {
        val result = validate(host = "not a host!!")
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_HOST_SYNTAX, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `port 0 is rejected`() {
        val result = validate(port = 0)
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_PORT, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `port above 65535 is rejected`() {
        val result = validate(port = 70000)
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_PORT, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `a malformed server public key is rejected`() {
        val result = validate(serverPublicKeyBase64 = "not-a-real-key")
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_SERVER_PUBLIC_KEY, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `an out-of-range client tunnel IP is rejected`() {
        val result = validate(clientTunnelIp = "999.999.999.999")
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_CLIENT_TUNNEL_IP, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `an out-of-range gateway tunnel IP is rejected`() {
        val result = validate(gatewayTunnelIp = "10.13.13.999")
        assertEquals(PrivateGatewayConfigFailureReason.INVALID_GATEWAY_TUNNEL_IP, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `a missing required magic header is rejected`() {
        val result = validate(awgProfile = validHeaders.copy(initPacketMagicHeader = null))
        assertEquals(PrivateGatewayConfigFailureReason.MISSING_REQUIRED_OBFUSCATION_HEADER, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `a blank required magic header is rejected, not just a null one`() {
        val result = validate(awgProfile = validHeaders.copy(transportPacketMagicHeader = "   "))
        assertEquals(PrivateGatewayConfigFailureReason.MISSING_REQUIRED_OBFUSCATION_HEADER, (result as PrivateGatewayValidationResult.Invalid).reason)
    }

    @Test
    fun `junk packet count size fields remain optional - AwgProfile-none-equivalent still passes once headers are present`() {
        val result = validate(awgProfile = validHeaders.copy(junkPacketCount = null, junkPacketMinSize = null, junkPacketMaxSize = null))
        assertTrue(result is PrivateGatewayValidationResult.Valid)
    }

    @Test
    fun `a valid config maps to a GatewayConfigSnapshot the existing GatewayConfigSnapshotValidator accepts identically`() {
        val config = (validate() as PrivateGatewayValidationResult.Valid).config
        val snapshot = config.toGatewayConfigSnapshot()

        val resolved = GatewayConfigSnapshotValidator.validate(snapshot)

        assertTrue(resolved is GatewayConfiguration.Configured)
        val configured = resolved as GatewayConfiguration.Configured
        assertEquals(config.host, configured.endpointHost)
        assertEquals(config.port, configured.endpointPort)
        assertEquals(config.serverPublicKeyBase64, configured.serverPublicKeyBase64)
        assertEquals(config.clientTunnelIp, configured.clientTunnelIp)
        assertEquals(listOf("0.0.0.0/0", "::/0"), configured.allowedIps)
    }

    @Test
    fun `PrivateGatewayConfig never carries a private key field - structural proof via reflection`() {
        val fieldNames = PrivateGatewayConfig::class.java.declaredFields.map { it.name.lowercase() }
        assertTrue(fieldNames.none { it.contains("private") && it.contains("key") })
    }
}
