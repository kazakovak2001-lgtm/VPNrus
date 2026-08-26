package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeGatewayConfigSource(
    private val host: String = "",
    private val port: String = "",
    private val publicKey: String = "",
    private val clientIp: String = "",
    private val gatewayIp: String = "",
) : GatewayConfigSource {
    override fun endpointHost() = host
    override fun endpointPort() = port
    override fun serverPublicKey() = publicKey
    override fun clientTunnelIp() = clientIp
    override fun gatewayTunnelIp() = gatewayIp
}

class GatewayConfigurationRepositoryTest {

    private val validKey = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y="

    @Test
    fun `all blank fields is Missing, not Invalid`() {
        val repo = DefaultGatewayConfigurationRepository(FakeGatewayConfigSource())
        assertEquals(GatewayConfiguration.Missing, repo.get())
    }

    @Test
    fun `fully valid config is Configured`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        val result = repo.get()
        assertTrue(result is GatewayConfiguration.Configured)
        result as GatewayConfiguration.Configured
        assertEquals("203.0.113.10", result.endpointHost)
        assertEquals(51820, result.endpointPort)
    }

    @Test
    fun `invalid endpoint port is rejected`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "not-a-port",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        assertTrue(repo.get() is GatewayConfiguration.Invalid)
    }

    @Test
    fun `out-of-range endpoint port is rejected`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "99999",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        assertTrue(repo.get() is GatewayConfiguration.Invalid)
    }

    @Test
    fun `malformed server public key is rejected`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = "not-a-real-key",
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        assertTrue(repo.get() is GatewayConfiguration.Invalid)
    }

    @Test
    fun `invalid client tunnel IP is rejected`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = validKey,
                clientIp = "not-an-ip",
                gatewayIp = "10.77.0.1",
            ),
        )
        assertTrue(repo.get() is GatewayConfiguration.Invalid)
    }

    @Test
    fun `blank endpoint host with other fields present is Invalid, not Missing`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        assertTrue(repo.get() is GatewayConfiguration.Invalid)
    }
}
