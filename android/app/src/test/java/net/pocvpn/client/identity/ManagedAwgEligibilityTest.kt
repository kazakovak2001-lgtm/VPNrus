package net.pocvpn.client.identity

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.PersistedProfile
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.identity.ManagedAwgEligibilityReason.AWG_ACTIVE
import net.pocvpn.client.identity.ManagedAwgEligibilityReason.BINDING_STORE_UNREADABLE
import net.pocvpn.client.identity.ManagedAwgEligibilityReason.IDENTITY_LIFECYCLE_BLOCKED
import net.pocvpn.client.identity.ManagedAwgEligibilityReason.IDENTITY_UNAVAILABLE
import net.pocvpn.client.identity.ManagedAwgEligibilityReason.REACTIVATION_REQUIRED
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.nio.file.Files

class ManagedAwgEligibilityTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val k0 = KeyPair().publicKey.toBase64()
    private val k1 = KeyPair().publicKey.toBase64()
    private val fp0 = ManagedAwgKeyFingerprint.of(k0)
    private val fp1 = ManagedAwgKeyFingerprint.of(k1)

    private fun eval(
        gateway: ProductionGatewayId = ProductionGatewayId.GERMANY,
        blocked: Boolean = false,
        bindings: ManagedAwgBindingLoadResult = ManagedAwgBindingLoadResult.Valid(mapOf(ProductionGatewayId.GERMANY to fp1)),
        key: ManagedKeyPeek = ManagedKeyPeek.Present(k1),
    ) = ManagedAwgEligibility.evaluate(gateway, blocked, bindings, key)

    @Test
    fun `matching key and per-gateway binding is eligible`() {
        assertEquals(AWG_ACTIVE, eval())
        assertTrue(ManagedAwgEligibility.isEligible(eval()))
    }

    @Test
    fun `missing binding for the gateway requires reactivation`() {
        assertEquals(REACTIVATION_REQUIRED, eval(gateway = ProductionGatewayId.STOCKHOLM))
        assertEquals(REACTIVATION_REQUIRED, eval(bindings = ManagedAwgBindingLoadResult.Absent))
    }

    @Test
    fun `mismatched key fingerprint requires reactivation`() {
        assertEquals(REACTIVATION_REQUIRED, eval(key = ManagedKeyPeek.Present(k0)))
    }

    @Test
    fun `missing, corrupted or malformed managed key is identity unavailable`() {
        assertEquals(IDENTITY_UNAVAILABLE, eval(key = ManagedKeyPeek.Absent))
        assertEquals(IDENTITY_UNAVAILABLE, eval(key = ManagedKeyPeek.Unavailable("corrupted")))
        assertEquals(IDENTITY_UNAVAILABLE, eval(key = ManagedKeyPeek.Present("garbage")))
    }

    @Test
    fun `unreadable binding store is never eligible`() {
        assertEquals(BINDING_STORE_UNREADABLE, eval(bindings = ManagedAwgBindingLoadResult.Unreadable("bad checksum")))
    }

    @Test
    fun `lifecycle block wins over an otherwise valid binding`() {
        assertEquals(IDENTITY_LIFECYCLE_BLOCKED, eval(blocked = true))
    }

    @Test
    fun `only AWG_ACTIVE is eligible`() {
        ManagedAwgEligibilityReason.entries.filter { it != AWG_ACTIVE }
            .forEach { assertFalse(ManagedAwgEligibility.isEligible(it)) }
    }

    @Test
    fun `Stockholm bound to K0 and Frankfurt bound to K1 with current K1`() {
        val bindings = ManagedAwgBindingLoadResult.Valid(
            mapOf(ProductionGatewayId.STOCKHOLM to fp0, ProductionGatewayId.GERMANY to fp1),
        )
        assertEquals(AWG_ACTIVE, eval(gateway = ProductionGatewayId.GERMANY, bindings = bindings))
        assertEquals(REACTIVATION_REQUIRED, eval(gateway = ProductionGatewayId.STOCKHOLM, bindings = bindings))
    }

    @Test
    fun `existing tunnel IP without a binding is not eligible`() = runBlocking {
        val tunnels = FileClientTunnelIdentityStore(tempFolder.newFolder("tunnel"))
        tunnels.write(ProductionGatewayId.STOCKHOLM, "10.77.0.4")
        val bindings = FileManagedAwgBindingStore(tempFolder.newFolder("binding"))

        assertEquals("10.77.0.4", tunnels.read(ProductionGatewayId.STOCKHOLM))
        assertEquals(
            REACTIVATION_REQUIRED,
            ManagedAwgEligibility.evaluate(ProductionGatewayId.STOCKHOLM, false, bindings.read(), ManagedKeyPeek.Present(k1)),
        )
    }

    @Test
    fun `legacy migration populates a tunnel IP but never creates a binding`() = runBlocking {
        val dir = tempFolder.newFolder("app")
        val tunnels = FileClientTunnelIdentityStore(dir)
        val bindings = FileManagedAwgBindingStore(dir)
        tunnels.migrateFromLegacyProvisionedProfile(
            PersistedProfile(
                endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
                endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
                gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
                clientTunnelIp = "10.77.0.5",
                gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
            ),
        )

        assertEquals("10.77.0.5", tunnels.read(ProductionGatewayId.GERMANY))
        assertEquals(ManagedAwgBindingLoadResult.Absent, bindings.read())
        assertEquals(
            REACTIVATION_REQUIRED,
            ManagedAwgEligibility.evaluate(ProductionGatewayId.GERMANY, false, bindings.read(), ManagedKeyPeek.Present(k1)),
        )
    }

    @Test
    fun `gate applies to managed AWG only, never to Xray or Hysteria2 transports`() {
        assertTrue(ManagedAwgEligibility.appliesTo(TransportKind.AMNEZIA_WG))
        TransportKind.entries.filter { it != TransportKind.AMNEZIA_WG }
            .forEach { assertFalse("$it must not be gated", ManagedAwgEligibility.appliesTo(it)) }
    }

    @Test
    fun `peek on the real repository never creates a key and reports state`() = runBlocking {
        val dir = Files.createTempDirectory("peek-test").toFile()
        val repo = AwgClientKeyRepository(FileIdentityStore(dir), FakeAesGcmKeyEncryptor())

        assertEquals(ManagedKeyPeek.Absent, repo.peekPublicKey())
        assertEquals(ManagedKeyPeek.Absent, repo.peekPublicKey()) // still nothing generated

        val created = repo.getOrCreateIdentity().publicKeyBase64
        assertEquals(ManagedKeyPeek.Present(created), repo.peekPublicKey())

        java.io.File(dir, "client_identity.bin").writeBytes(byteArrayOf(0, 0, 0, 9))
        assertTrue(repo.peekPublicKey() is ManagedKeyPeek.Unavailable)
    }
}
