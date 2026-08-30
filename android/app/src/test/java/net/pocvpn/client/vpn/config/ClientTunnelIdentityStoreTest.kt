package net.pocvpn.client.vpn.config

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * B13 review fix - proves the per-device, per-endpoint client tunnel
 * identity store: independent Germany/Stockholm assignments, no cross-
 * endpoint leakage, fail-closed on a missing endpoint, persistence across
 * restart, and the evidence-based legacy migration (a SECOND review fix -
 * the first migration unconditionally seeded every install with this test
 * device's own hardcoded IPs, which is exactly the bug this store exists
 * to remove).
 */
class ClientTunnelIdentityStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val realGermanyHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost

    private fun legacyProfile(
        endpointHost: String = realGermanyHost,
        clientTunnelIp: String = "10.77.0.5",
    ) = PersistedProfile(
        endpointHost = endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        clientTunnelIp = clientTunnelIp,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
    )

    @Test
    fun `two endpoints on one device get independent client tunnel IPs`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.write(ProductionGatewayId.GERMANY, "10.77.0.5")
        store.write(ProductionGatewayId.STOCKHOLM, "10.77.0.2")

        assertEquals("10.77.0.5", store.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `writing one endpoint never leaks into or overwrites the other`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.write(ProductionGatewayId.GERMANY, "10.77.0.5")

        assertNull(store.read(ProductionGatewayId.STOCKHOLM))

        store.write(ProductionGatewayId.STOCKHOLM, "10.77.0.2")
        assertEquals("10.77.0.5", store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `missing endpoint identity reads null - fail closed, never a fallback value`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        assertNull(store.read(ProductionGatewayId.GERMANY))
        assertNull(store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `write rejects a structurally invalid IPv4 address`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        assertThrows(IllegalArgumentException::class.java) {
            store.write(ProductionGatewayId.GERMANY, "not-an-ip")
        }
    }

    @Test
    fun `persists across a restart - a fresh store instance over the same directory reads the same values`() {
        val first = FileClientTunnelIdentityStore(tempFolder.root)
        first.write(ProductionGatewayId.GERMANY, "10.77.0.5")
        first.write(ProductionGatewayId.STOCKHOLM, "10.77.0.2")

        val second = FileClientTunnelIdentityStore(tempFolder.root)
        assertEquals("10.77.0.5", second.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", second.read(ProductionGatewayId.STOCKHOLM))
    }

    // --- B13 SECOND review fix: evidence-based migration only ---

    @Test
    fun `fresh install - no legacy profile means nothing is seeded for either endpoint`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(null)

        assertNull(store.read(ProductionGatewayId.GERMANY))
        assertNull(store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `eligible legacy install - a real persisted Germany profile migrates its own tunnel IP`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(legacyProfile(clientTunnelIp = "10.77.0.5"))

        assertEquals("10.77.0.5", store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `migration never invents a Stockholm assignment - no legacy evidence can exist for it`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(legacyProfile(clientTunnelIp = "10.77.0.5"))

        assertNull(store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `a persisted profile activated against a different host is not treated as Germany evidence`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(
            legacyProfile(endpointHost = "203.0.113.9", clientTunnelIp = "10.77.0.5")
        )

        assertNull(store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `migration is idempotent - calling it again with the same profile changes nothing`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        val profile = legacyProfile(clientTunnelIp = "10.77.0.5")

        store.migrateFromLegacyProvisionedProfile(profile)
        store.migrateFromLegacyProvisionedProfile(profile)

        assertEquals("10.77.0.5", store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `existing stored values are never overwritten by a later migration attempt`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.write(ProductionGatewayId.GERMANY, "10.77.0.99")

        store.migrateFromLegacyProvisionedProfile(legacyProfile(clientTunnelIp = "10.77.0.5"))

        assertEquals("10.77.0.99", store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `missing endpoint assignment still fails closed after a partial migration`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(legacyProfile(clientTunnelIp = "10.77.0.5"))

        // Germany is now provisioned, Stockholm is still not - and must
        // resolve through SelectedProductionGatewaySource as a fail-closed
        // Invalid, never a silent substitute of Germany's value.
        val stockholmSource = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, store::read)
        assertEquals("", stockholmSource.clientTunnelIp())

        val config = DefaultGatewayConfigurationRepository(stockholmSource).get()
        assert(config is GatewayConfiguration.Invalid) { "expected Invalid, got $config" }
    }

    @Test
    fun `a persisted profile with Germany's host but a different port is not treated as Germany evidence`() {
        // B13 consolidated review fix (finding 7) - host alone is too weak
        // a signal; matchGatewayId requires host AND port AND key together.
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(
            legacyProfile(clientTunnelIp = "10.77.0.5").copy(endpointPort = 51821)
        )

        assertNull(store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `a persisted profile with Germany's host and port but a rotated-wrong key is not treated as Germany evidence`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(
            legacyProfile(clientTunnelIp = "10.77.0.5").copy(gatewayPublicKey = "XgskJjlpQrp+75Bdnz+yDGJYnv7E6Zd60BJWWj1j5Wk=")
        )

        assertNull(store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `a corrupted out-of-range stored IP is never read back as a provisioned identity`() {
        // B13 consolidated review fix (finding 7) - Ipv4Format.isValid (all
        // octets 0..255), not a shape-only regex: a hand-edited/corrupted
        // file with "999.999.999.999" must not make Germany appear
        // provisioned.
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        java.io.File(tempFolder.root, "client_tunnel_identity.txt").writeText("GERMANY=999.999.999.999")

        assertNull(store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `Germany and Stockholm selection resolves correctly through SelectedProductionGatewaySource after migration`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateFromLegacyProvisionedProfile(legacyProfile(clientTunnelIp = "10.77.0.5"))
        store.write(ProductionGatewayId.STOCKHOLM, "10.77.0.2")

        val germanySource = SelectedProductionGatewaySource({ ProductionGatewayId.GERMANY }, store::read)
        val stockholmSource = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, store::read)

        assertEquals("10.77.0.5", germanySource.clientTunnelIp())
        assertEquals("10.77.0.2", stockholmSource.clientTunnelIp())
    }
}
