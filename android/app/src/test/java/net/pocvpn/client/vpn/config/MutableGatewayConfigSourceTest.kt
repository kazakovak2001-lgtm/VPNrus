package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeDelegateSource(
    private val host: String = "",
    private val port: String = "",
    private val publicKey: String = "",
    private val clientIp: String = "",
    private val gatewayIp: String = "",
    private val allowedIps: String = "narrow-test-route",
) : GatewayConfigSource {
    override fun endpointHost() = host
    override fun endpointPort() = port
    override fun serverPublicKey() = publicKey
    override fun clientTunnelIp() = clientIp
    override fun gatewayTunnelIp() = gatewayIp
    override fun allowedIps() = allowedIps
}

/**
 * B8B3B - narrow tests for the new boundary only: validated provisioning
 * values map through to the AWG profile fields, AWG obfuscation parameters
 * (carried on GatewayConfiguration.Configured.profile) are untouched, and a
 * malformed value still cannot produce a Configured result even if it
 * somehow reached apply().
 */
class MutableGatewayConfigSourceTest {

    private val serverKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU="

    @Test
    fun `before apply, every field delegates unchanged`() {
        val delegate = FakeDelegateSource(host = "dev.example", port = "51820", publicKey = serverKey, clientIp = "10.9.0.2", gatewayIp = "10.9.0.1")
        val source = MutableGatewayConfigSource(delegate)

        assertEquals(delegate.endpointHost(), source.endpointHost())
        assertEquals(delegate.endpointPort(), source.endpointPort())
        assertEquals(delegate.serverPublicKey(), source.serverPublicKey())
        assertEquals(delegate.clientTunnelIp(), source.clientTunnelIp())
        assertEquals(delegate.gatewayTunnelIp(), source.gatewayTunnelIp())
        assertEquals(delegate.allowedIps(), source.allowedIps())
    }

    @Test
    fun `apply overrides exactly the five provisioning-derived fields`() {
        val delegate = FakeDelegateSource()
        val source = MutableGatewayConfigSource(delegate)

        source.apply(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKey = serverKey,
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
        )

        assertEquals("152.70.43.1", source.endpointHost())
        assertEquals("51820", source.endpointPort())
        assertEquals(serverKey, source.serverPublicKey())
        assertEquals("10.77.0.2", source.clientTunnelIp())
        assertEquals("10.77.0.1", source.gatewayTunnelIp())
        // AllowedIPs is not part of the provisioning response - always the delegate's value.
        assertEquals("narrow-test-route", source.allowedIps())
    }

    @Test
    fun `applied values flow through DefaultGatewayConfigurationRepository into Configured`() {
        val source = MutableGatewayConfigSource(FakeDelegateSource())
        source.apply(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKey = serverKey,
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
        )

        val config = DefaultGatewayConfigurationRepository(source).get()
        assertTrue(config is GatewayConfiguration.Configured)
        val configured = config as GatewayConfiguration.Configured
        assertEquals("152.70.43.1", configured.endpointHost)
        assertEquals(51820, configured.endpointPort)
        assertEquals(serverKey, configured.serverPublicKeyBase64)
        assertEquals("10.77.0.2", configured.clientTunnelIp)
        assertEquals("10.77.0.1", configured.gatewayTunnelIp)
    }

    @Test
    fun `AWG obfuscation profile is untouched by apply - same PocAwgProfile instance`() {
        val source = MutableGatewayConfigSource(FakeDelegateSource())
        source.apply(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKey = serverKey,
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
        )

        val configured = DefaultGatewayConfigurationRepository(source).get() as GatewayConfiguration.Configured
        // Identity check, not just equality: this boundary must not construct
        // or mutate a profile of its own - Jc/Jmin/Jmax/S1-4/H1-4 stay exactly
        // PocAwgProfile.value, unchanged by this slice.
        assertSame(PocAwgProfile.value, configured.profile)
    }

    @Test
    fun `a malformed value cannot produce Configured even if it reached apply`() {
        // Defense in depth: even if a bad value somehow reached apply()
        // (it cannot in practice - MainViewModel only calls apply() from
        // ProvisioningResult.Success, which ProvisioningClient only ever
        // constructs after its own structural validation passes) -
        // DefaultGatewayConfigurationRepository's own validation still
        // refuses to produce a Configured result.
        val source = MutableGatewayConfigSource(FakeDelegateSource())
        source.apply(
            endpointHost = "152.70.43.1",
            endpointPort = 51820,
            serverPublicKey = "not-a-real-key",
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
        )

        val config = DefaultGatewayConfigurationRepository(source).get()
        assertTrue(config is GatewayConfiguration.Invalid)
    }
}
