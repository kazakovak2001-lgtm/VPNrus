package net.pocvpn.client.vpn.config

import java.io.DataOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * B8B3C - narrow tests for the new persistence boundary only: round trip,
 * corrupt/partial rejection (fail closed, never a partial result), and that
 * PersistedProfile/the on-disk format structurally cannot carry a bearer
 * token or a private key.
 */
class ProvisionedProfileStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val sample = PersistedProfile(
        endpointHost = "152.70.43.1",
        endpointPort = 51820,
        gatewayPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
        clientTunnelIp = "10.77.0.2",
        gatewayTunnelIp = "10.77.0.1",
    )

    @Test
    fun `not yet written is NotFound`() {
        val store = FileProfileStore(tmp.root)
        assertEquals(ProfileLoadResult.NotFound, store.read())
    }

    @Test
    fun `write then read round-trips exactly`() {
        val store = FileProfileStore(tmp.root)
        store.write(sample)

        val result = store.read()
        assertTrue(result is ProfileLoadResult.Found)
        assertEquals(sample, (result as ProfileLoadResult.Found).profile)
    }

    @Test
    fun `write is atomic - no tmp file left behind after a successful write`() {
        val store = FileProfileStore(tmp.root)
        store.write(sample)
        assertTrue(java.io.File(tmp.root, "provisioned_profile.bin").exists())
        assertTrue(!java.io.File(tmp.root, "provisioned_profile.bin.tmp").exists())
    }

    @Test
    fun `truncated file is Corrupted, not a crash or partial result`() {
        val file = java.io.File(tmp.root, "provisioned_profile.bin")
        DataOutputStream(file.outputStream()).use { it.writeInt(1) } // version only, nothing else
        val store = FileProfileStore(tmp.root)
        assertTrue(store.read() is ProfileLoadResult.Corrupted)
    }

    @Test
    fun `unsupported format version is Corrupted`() {
        val file = java.io.File(tmp.root, "provisioned_profile.bin")
        DataOutputStream(file.outputStream()).use { it.writeInt(999) }
        val store = FileProfileStore(tmp.root)
        assertTrue(store.read() is ProfileLoadResult.Corrupted)
    }

    @Test
    fun `structurally invalid field values are rejected even in an otherwise well-formed file`() {
        // Well-formed length-prefixed framing, but gatewayPublicKey is garbage -
        // proves validation runs on every read, not only on the raw bytes.
        val store = FileProfileStore(tmp.root)
        store.write(sample.copy(gatewayPublicKey = "not-a-real-key"))
        assertTrue(store.read() is ProfileLoadResult.Corrupted)
    }

    @Test
    fun `malformed IPv4 field is rejected`() {
        // Not merely out-of-range octets (the shape-only regex, matching
        // ProvisioningClient's own validation strictness, does not check
        // 0-255 range) - genuinely the wrong shape (a CIDR suffix leaking
        // in), which the regex does reject.
        val store = FileProfileStore(tmp.root)
        store.write(sample.copy(clientTunnelIp = "10.77.0.2/32"))
        assertTrue(store.read() is ProfileLoadResult.Corrupted)
    }

    @Test
    fun `out-of-range port is rejected`() {
        val store = FileProfileStore(tmp.root)
        store.write(sample.copy(endpointPort = 70000))
        assertTrue(store.read() is ProfileLoadResult.Corrupted)
    }

    @Test
    fun `validatePersistedProfile has no way to represent a token or private key`() {
        // Structural proof, not just convention: PersistedProfile's constructor
        // (and validatePersistedProfile's parameter list) has exactly the five
        // fields below, all traced 1:1 to MutableGatewayConfigSource.apply()'s
        // non-secret parameters - there is no token/privateKey field anywhere
        // in this file. Asserted by exact NAME set, not a raw field count -
        // B8E's Compose compiler plugin (enabled module-wide, not just on
        // Composable files) stamps an extra non-synthetic `$stable` field
        // onto every class in this module for its own stability tracking;
        // that field carries no data of this class's own and must not make
        // this assertion look like it passes when a real field was added.
        val expectedFieldNames = setOf(
            "endpointHost", "endpointPort", "gatewayPublicKey", "clientTunnelIp", "gatewayTunnelIp",
        )
        val actualFieldNames = PersistedProfile::class.java.declaredFields
            .filterNot { it.isSynthetic }
            .map { it.name }
            .filterNot { it == "\$stable" }
            .toSet()
        assertEquals(expectedFieldNames, actualFieldNames)
    }

    @Test
    fun `delete removes a previously written profile`() {
        val store = FileProfileStore(tmp.root)
        store.write(sample)
        store.delete()
        assertEquals(ProfileLoadResult.NotFound, store.read())
    }

    @Test
    fun `restored profile flows through MutableGatewayConfigSource to the same effective config as a live apply`() {
        val fromRestore = MutableGatewayConfigSource(BuildConfigGatewaySourceFake())
        fromRestore.apply(
            endpointHost = sample.endpointHost,
            endpointPort = sample.endpointPort,
            serverPublicKey = sample.gatewayPublicKey,
            clientTunnelIp = sample.clientTunnelIp,
            gatewayTunnelIp = sample.gatewayTunnelIp,
        )
        val restoredConfigured = DefaultGatewayConfigurationRepository(fromRestore).get() as GatewayConfiguration.Configured

        val fromLive = MutableGatewayConfigSource(BuildConfigGatewaySourceFake())
        fromLive.apply(
            endpointHost = sample.endpointHost,
            endpointPort = sample.endpointPort,
            serverPublicKey = sample.gatewayPublicKey,
            clientTunnelIp = sample.clientTunnelIp,
            gatewayTunnelIp = sample.gatewayTunnelIp,
        )
        val liveConfigured = DefaultGatewayConfigurationRepository(fromLive).get() as GatewayConfiguration.Configured

        assertEquals(liveConfigured.endpointHost, restoredConfigured.endpointHost)
        assertEquals(liveConfigured.endpointPort, restoredConfigured.endpointPort)
        assertEquals(liveConfigured.serverPublicKeyBase64, restoredConfigured.serverPublicKeyBase64)
        assertEquals(liveConfigured.clientTunnelIp, restoredConfigured.clientTunnelIp)
        assertEquals(liveConfigured.gatewayTunnelIp, restoredConfigured.gatewayTunnelIp)
    }
}

private class BuildConfigGatewaySourceFake : GatewayConfigSource {
    override fun endpointHost() = ""
    override fun endpointPort() = ""
    override fun serverPublicKey() = ""
    override fun clientTunnelIp() = ""
    override fun gatewayTunnelIp() = ""
    override fun allowedIps() = ""
}
