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
 * restart, and the one-time legacy-defaults migration.
 */
class ClientTunnelIdentityStoreTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

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

    @Test
    fun `migration seeds both legacy defaults on a fresh device with no stored identity`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateLegacyDefaultsIfMissing()

        assertEquals("10.77.0.5", store.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `migration preserves the currently provisioned physical device - never overwrites an existing value`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.write(ProductionGatewayId.GERMANY, "10.77.0.99")

        store.migrateLegacyDefaultsIfMissing()

        // Germany already had a real, current value - migration must not
        // clobber it. Stockholm had none, so it gets seeded.
        assertEquals("10.77.0.99", store.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", store.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `migration is idempotent - calling it again after a real value is set does not revert it`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateLegacyDefaultsIfMissing()
        store.write(ProductionGatewayId.GERMANY, "10.77.0.42")

        store.migrateLegacyDefaultsIfMissing()

        assertEquals("10.77.0.42", store.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `Germany and Stockholm selection resolves correctly through SelectedProductionGatewaySource end to end`() {
        val store = FileClientTunnelIdentityStore(tempFolder.root)
        store.migrateLegacyDefaultsIfMissing()

        val germanySource = SelectedProductionGatewaySource({ ProductionGatewayId.GERMANY }, store::read)
        val stockholmSource = SelectedProductionGatewaySource({ ProductionGatewayId.STOCKHOLM }, store::read)

        assertEquals("10.77.0.5", germanySource.clientTunnelIp())
        assertEquals("10.77.0.2", stockholmSource.clientTunnelIp())
    }
}
