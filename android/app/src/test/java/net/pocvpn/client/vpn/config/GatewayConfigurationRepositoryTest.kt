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
    private val allowedIps: String = "",
) : GatewayConfigSource {
    override fun endpointHost() = host
    override fun endpointPort() = port
    override fun serverPublicKey() = publicKey
    override fun clientTunnelIp() = clientIp
    override fun gatewayTunnelIp() = gatewayIp
    override fun allowedIps() = allowedIps
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
    fun `unset allowedIps defaults to full-tunnel routing`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        val result = repo.get() as GatewayConfiguration.Configured
        assertEquals(listOf("0.0.0.0/0", "::/0"), result.allowedIps)
    }

    @Test
    fun `allowedIps override narrows routing to the given CIDR`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "172.27.193.89",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
                allowedIps = "10.77.0.0/24",
            ),
        )
        val result = repo.get() as GatewayConfiguration.Configured
        assertEquals(listOf("10.77.0.0/24"), result.allowedIps)
    }

    // --- B8F: DNS + IPv6 leak protection ---

    @Test
    fun `effective config carries the canonical DNS resolver policy`() {
        val repo = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
            ),
        )
        val result = repo.get() as GatewayConfiguration.Configured
        assertEquals(VpnDnsPolicy.servers, result.dnsServers)
        assertEquals(listOf("1.1.1.1", "1.0.0.1"), result.dnsServers)
    }

    @Test
    fun `dual-stack full-tunnel is the default even with an allowedIps override present for a different purpose`() {
        // Requirement 4: nothing other than an explicit, non-blank
        // GatewayConfigSource.allowedIps() override can ever narrow away
        // from the dual-stack (0.0.0.0/0 + ::/0) default - there is no
        // separate "IPv4-only" code path this could silently take.
        val repoWithoutOverride = DefaultGatewayConfigurationRepository(
            FakeGatewayConfigSource(
                host = "203.0.113.10",
                port = "51820",
                publicKey = validKey,
                clientIp = "10.77.0.2",
                gatewayIp = "10.77.0.1",
                allowedIps = "", // blank = no explicit policy change
            ),
        )
        val result = repoWithoutOverride.get() as GatewayConfiguration.Configured
        assertTrue(result.allowedIps.contains("0.0.0.0/0"))
        assertTrue(result.allowedIps.contains("::/0"))
    }

    @Test
    fun `restored-profile-shaped source and dev-fallback-shaped source converge on the identical DNS and AllowedIPs policy`() {
        // Requirement 5: DNS/IPv6 policy is applied in exactly ONE place
        // (DefaultGatewayConfigurationRepository.get()) that every profile
        // source already converges through - so a source standing in for a
        // RESTORED_PERSISTED profile and one standing in for a fresh
        // DEV_FALLBACK/provisioned profile must produce the SAME policy,
        // with no per-source DNS/AllowedIps wiring anywhere to drift.
        val restoredShapedSource = FakeGatewayConfigSource(
            host = "152.70.43.1",
            port = "51820",
            publicKey = validKey,
            clientIp = "10.77.0.9",
            gatewayIp = "10.77.0.1",
        )
        val devFallbackShapedSource = FakeGatewayConfigSource(
            host = "dev.example",
            port = "51820",
            publicKey = validKey,
            clientIp = "10.9.0.2",
            gatewayIp = "10.9.0.1",
        )

        val restored = DefaultGatewayConfigurationRepository(restoredShapedSource).get() as GatewayConfiguration.Configured
        val devFallback = DefaultGatewayConfigurationRepository(devFallbackShapedSource).get() as GatewayConfiguration.Configured

        assertEquals(restored.dnsServers, devFallback.dnsServers)
        assertEquals(restored.allowedIps, devFallback.allowedIps)
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
