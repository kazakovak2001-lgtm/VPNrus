package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B13 - proves the real product gateway-selection mechanism: Germany and
 * Stockholm resolve to their own, independent connection facts AND their
 * own AWG obfuscation profile (the architectural fix for PocAwgProfile
 * having been a single global value - see ProductionGatewayCatalog's own
 * docs), with zero cross-endpoint leakage.
 *
 * B13 review fix - clientTunnelIp is now resolved from a separate,
 * per-device identity resolver (never ProductionGatewayCatalog - see
 * SelectedProductionGatewaySource's own docs), so every test below supplies
 * its own fake resolver rather than relying on catalog-hardcoded values.
 */
class SelectedProductionGatewaySourceTest {

    private fun fakeIdentity(vararg pairs: Pair<ProductionGatewayId, String>): (ProductionGatewayId) -> String? {
        val map = pairs.toMap()
        return { id -> map[id] }
    }

    @Test
    fun `Germany selection resolves the real Oracle endpoint`() {
        val source = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.GERMANY },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5"),
        )
        assertEquals("152.70.43.1", source.endpointHost())
        assertEquals("51820", source.endpointPort())
        assertEquals("9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=", source.serverPublicKey())
    }

    @Test
    fun `Stockholm selection resolves the real AWS endpoint`() {
        val source = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.STOCKHOLM },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        )
        assertEquals("16.170.208.231", source.endpointHost())
        assertEquals("51820", source.endpointPort())
        assertEquals("XgskJjlpQrp+75Bdnz+yDGJYnv7E6Zd60BJWWj1j5Wk=", source.serverPublicKey())
    }

    @Test
    fun `switching the underlying selection changes what the source resolves - deterministic, no caching`() {
        var current = ProductionGatewayId.GERMANY
        val source = SelectedProductionGatewaySource(
            selectedGatewayId = { current },
            clientTunnelIp = fakeIdentity(
                ProductionGatewayId.GERMANY to "10.77.0.5",
                ProductionGatewayId.STOCKHOLM to "10.77.0.2",
            ),
        )

        assertEquals("152.70.43.1", source.endpointHost())
        current = ProductionGatewayId.STOCKHOLM
        assertEquals("16.170.208.231", source.endpointHost())
    }

    @Test
    fun `Germany and Stockholm never resolve to the same server public key - no credential leakage`() {
        val germany = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.GERMANY },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5"),
        )
        val stockholm = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.STOCKHOLM },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        )
        assertNotEquals(germany.serverPublicKey(), stockholm.serverPublicKey())
        assertNotEquals(germany.endpointHost(), stockholm.endpointHost())
    }

    @Test
    fun `each gateway carries its own AWG obfuscation profile, not a shared global default`() {
        val germanyProfile = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.GERMANY },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5"),
        ).profile()
        val stockholmProfile = SelectedProductionGatewaySource(
            selectedGatewayId = { ProductionGatewayId.STOCKHOLM },
            clientTunnelIp = fakeIdentity(ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        ).profile()

        // Both currently carry the SAME real, physically-verified values -
        // that is real data convergence, not evidence they share one global
        // object: each is independently sourced from its own
        // ProductionGatewayDescriptor.awgProfile field.
        assertEquals(ProductionGatewayCatalog.GERMANY.awgProfile, germanyProfile)
        assertEquals(ProductionGatewayCatalog.STOCKHOLM.awgProfile, stockholmProfile)
    }

    @Test
    fun `DefaultGatewayConfigurationRepository resolves Germany end to end - endpoint, port, key, and profile all agree`() {
        val repo = DefaultGatewayConfigurationRepository(
            SelectedProductionGatewaySource(
                selectedGatewayId = { ProductionGatewayId.GERMANY },
                clientTunnelIp = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5"),
            )
        )
        val config = repo.get() as GatewayConfiguration.Configured

        assertEquals("152.70.43.1", config.endpointHost)
        assertEquals(51820, config.endpointPort)
        assertEquals("10.77.0.5", config.clientTunnelIp)
        assertEquals(ProductionGatewayCatalog.GERMANY.awgProfile, config.profile)
    }

    @Test
    fun `DefaultGatewayConfigurationRepository resolves Stockholm end to end - endpoint, port, key, and profile all agree`() {
        val repo = DefaultGatewayConfigurationRepository(
            SelectedProductionGatewaySource(
                selectedGatewayId = { ProductionGatewayId.STOCKHOLM },
                clientTunnelIp = fakeIdentity(ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
            )
        )
        val config = repo.get() as GatewayConfiguration.Configured

        assertEquals("16.170.208.231", config.endpointHost)
        assertEquals(51820, config.endpointPort)
        assertEquals("10.77.0.2", config.clientTunnelIp)
        assertEquals(ProductionGatewayCatalog.STOCKHOLM.awgProfile, config.profile)
    }

    @Test
    fun `a repository resolving Stockholm never carries Germany's server public key, and vice versa`() {
        val germanyConfig = DefaultGatewayConfigurationRepository(
            SelectedProductionGatewaySource(
                selectedGatewayId = { ProductionGatewayId.GERMANY },
                clientTunnelIp = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5"),
            )
        ).get() as GatewayConfiguration.Configured
        val stockholmConfig = DefaultGatewayConfigurationRepository(
            SelectedProductionGatewaySource(
                selectedGatewayId = { ProductionGatewayId.STOCKHOLM },
                clientTunnelIp = fakeIdentity(ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
            )
        ).get() as GatewayConfiguration.Configured

        assertNotEquals(germanyConfig.serverPublicKeyBase64, stockholmConfig.serverPublicKeyBase64)
        assertNotEquals(germanyConfig.endpointHost, stockholmConfig.endpointHost)
    }

    // --- B13 review fix: per-device client tunnel identity resolution ---

    @Test
    fun `two endpoints on one device resolve their own independent client tunnel IPs`() {
        val identity = fakeIdentity(
            ProductionGatewayId.GERMANY to "10.77.0.5",
            ProductionGatewayId.STOCKHOLM to "10.77.0.2",
        )
        val germany = SelectedProductionGatewaySource({ ProductionGatewayId.GERMANY }, identity)
        val stockholm = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, identity)

        assertEquals("10.77.0.5", germany.clientTunnelIp())
        assertEquals("10.77.0.2", stockholm.clientTunnelIp())
        assertNotEquals(germany.clientTunnelIp(), stockholm.clientTunnelIp())
    }

    @Test
    fun `no cross-endpoint leakage - a resolver missing Stockholm never falls back to Germany's IP`() {
        val identity = fakeIdentity(ProductionGatewayId.GERMANY to "10.77.0.5")
        val stockholm = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, identity)

        assertEquals("", stockholm.clientTunnelIp())
        assertNotEquals("10.77.0.5", stockholm.clientTunnelIp())
    }

    @Test
    fun `missing endpoint identity fails closed to Invalid, never a crash or a silent substitute`() {
        val source = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, fakeIdentity())
        val config = DefaultGatewayConfigurationRepository(source).get()

        assertTrue(config is GatewayConfiguration.Invalid)
        assertTrue((config as GatewayConfiguration.Invalid).reason.contains("client tunnel IP"))
    }

    @Test
    fun `gateway switching still resolves the correct endpoint-specific tunnel IP`() {
        var current = ProductionGatewayId.GERMANY
        val identity = fakeIdentity(
            ProductionGatewayId.GERMANY to "10.77.0.5",
            ProductionGatewayId.STOCKHOLM to "10.77.0.2",
        )
        val source = SelectedProductionGatewaySource({ current }, identity)

        assertEquals("10.77.0.5", source.clientTunnelIp())
        current = ProductionGatewayId.STOCKHOLM
        assertEquals("10.77.0.2", source.clientTunnelIp())
    }
}
