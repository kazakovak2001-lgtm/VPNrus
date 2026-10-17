@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.AwgClientKeyRepository
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileIdentityStore
import net.pocvpn.client.identity.FileManagedAwgBindingStore
import net.pocvpn.client.identity.ManagedAwgIdentityGuard
import net.pocvpn.client.identity.ManagedAwgKeyFingerprint
import net.pocvpn.client.identity.ManagedIdentityLifecycle
import net.pocvpn.client.identity.ManagedKeyPeek
import net.pocvpn.client.identity.PersistedIdentity
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Hysteria2Profile
import net.pocvpn.client.reachability.Shadowsocks2022Profile
import net.pocvpn.client.reachability.withHysteria2Profile
import net.pocvpn.client.reachability.withShadowsocks2022Profile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.amnezia.awg.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * Phase B step 2 - managed AWG may only start with an existing key whose
 * fingerprint is bound to the exact gateway; every other state fails closed
 * BEFORE the transport is touched. PRIVATE, Shadowsocks and Hysteria2 are
 * never gated.
 */
class VpnControllerManagedAwgBindingTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun configuredGateway() = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10",
        endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2", // a stored tunnel IP exists in every test
        gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0"),
        profile = AwgProfile.none(),
    )

    private class Env(val dir: File) {
        val encryptor = FakeAesGcmKeyEncryptor()
        val repo = AwgClientKeyRepository(FileIdentityStore(dir), encryptor)
        val bindings = FileManagedAwgBindingStore(dir)
        // Current stored tunnel IP = the one configuredGateway() uses (IP "A").
        val tunnels = FileClientTunnelIdentityStore(dir).also { it.write(ProductionGatewayId.GERMANY, "10.77.0.2") }
        val guard = ManagedAwgIdentityGuard(ManagedIdentityLifecycle(), bindings, tunnels::read)
        val identityFile = File(dir, "client_identity.bin")

        suspend fun createKey(): String = repo.getOrCreateIdentity().publicKeyBase64
        suspend fun bind(gateway: ProductionGatewayId, publicKey: String) {
            bindings.updateGateway(gateway, ManagedAwgKeyFingerprint.of(publicKey)) { ManagedKeyPeek.Present(publicKey) }
        }
    }

    private fun env() = Env(tmp.newFolder())

    private fun TestScope.controller(
        env: Env,
        transport: VpnTransport = FakeVpnTransport(),
        diagnostics: DiagnosticsStore = DiagnosticsStore(),
        reconnectManager: FakeReconnectManager = FakeReconnectManager(),
        shadowsocks: FakeVpnTransport? = null,
        hysteria2: FakeVpnTransport? = null,
    ) = VpnController(
        transport, env.repo,
        FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager, diagnostics, backgroundScope,
        shadowsocksTransport = shadowsocks,
        hysteria2Transport = hysteria2,
        managedAwgIdentityGuard = env.guard,
    )

    private fun assertRefused(transport: FakeVpnTransport, controller: VpnController, diagnostics: DiagnosticsStore, reason: String) {
        assertEquals("AWG transport must never be started", 0, transport.connectCallCount)
        assertTrue("expected Error, was ${controller.state.value}", controller.state.value is TransportState.Error)
        assertEquals(VpnError.ConfigurationMappingFailure("MANAGED_AWG_$reason"), diagnostics.snapshot.value.lastError)
    }

    // --- eligibility at the config-build choke point ---

    @Test
    fun `valid binding and matching key starts AWG with exactly that key`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        val controller = controller(env, transport)

        controller.connect()
        runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
        val sentKey = (transport.lastConfig as TransportConfig.Awg).config.privateKeyBase64
        assertTrue("tunnel must use the bound key", sentKey == env.repo.getPrivateKeyForTunnel())
    }

    @Test
    fun `stored tunnel IP without a binding never authorizes AWG`() = runTest {
        val env = env()
        env.createKey()
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "REACTIVATION_REQUIRED")
    }

    @Test
    fun `unreadable binding store blocks AWG`() = runTest {
        val env = env()
        env.createKey()
        File(env.dir, "managed_awg_binding.bin").writeBytes(ByteArray(24) { 7 })
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "BINDING_STORE_UNREADABLE")
    }

    @Test
    fun `binding for Stockholm does not authorize Frankfurt`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.STOCKHOLM, publicKey)
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect() // default attempt targets the frankfurt endpoint
        runCurrent()

        assertRefused(transport, controller, diagnostics, "REACTIVATION_REQUIRED")
    }

    @Test
    fun `binding from a previous key does not authorize the current key`() = runTest {
        val env = env()
        env.bind(ProductionGatewayId.GERMANY, KeyPair().publicKey.toBase64()) // old key K0
        env.createKey() // current key K1
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "REACTIVATION_REQUIRED")
    }

    @Test
    fun `missing managed identity is refused and no key is created`() = runTest {
        val env = env()
        env.bind(ProductionGatewayId.GERMANY, KeyPair().publicKey.toBase64())
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "IDENTITY_UNAVAILABLE")
        assertFalse("AWG config construction must never create a key", env.identityFile.exists())
    }

    @Test
    fun `mismatched stored key pair cannot authorize AWG even when the public key is bound`() = runTest {
        val env = env()
        val storedPublic = KeyPair().publicKey.toBase64()
        val unrelatedPrivate = KeyPair().privateKey.toBase64()
        FileIdentityStore(env.dir).write(PersistedIdentity(env.encryptor.encrypt(unrelatedPrivate.toByteArray()), storedPublic))
        env.bind(ProductionGatewayId.GERMANY, storedPublic)
        val before = env.identityFile.readBytes()
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "IDENTITY_UNAVAILABLE")
        assertTrue(before.contentEquals(env.identityFile.readBytes()))
    }

    // --- N-1: tunnel IP snapshot vs L ---

    @Test
    fun `activation that changes the tunnel IP while the connect waits for L refuses the stale config`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey) // valid binding + IP A
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)
        val commitMayFinish = CompletableDeferred<Unit>()
        val lHeld = CompletableDeferred<Unit>()

        // Stands in for commitManagedActivationLocally: holds L, writes IP B, then the binding.
        backgroundScope.launch {
            env.guard.lifecycle.withLock {
                lHeld.complete(Unit)
                commitMayFinish.await()
                env.tunnels.write(ProductionGatewayId.GERMANY, "10.77.0.9")
                env.bind(ProductionGatewayId.GERMANY, publicKey)
            }
        }
        lHeld.await()
        // The connect resolves its config (IP A) before L, then blocks on L.
        val connectJob = backgroundScope.launch { controller.connect() }
        runCurrent()
        assertEquals(0, transport.connectCallCount)

        commitMayFinish.complete(Unit)
        runCurrent()
        connectJob.join()

        assertRefused(transport, controller, diagnostics, "TUNNEL_IDENTITY_CHANGED")
        assertEquals(null, transport.lastConfig)
    }

    @Test
    fun `missing current tunnel IP refuses AWG even with a valid binding`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        File(env.dir, "client_tunnel_identity.txt").delete()
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)

        controller.connect()
        runCurrent()

        assertRefused(transport, controller, diagnostics, "TUNNEL_IDENTITY_CHANGED")
    }

    // --- non-gated paths ---

    @Test
    fun `PRIVATE attempt is never gated and does not take the lifecycle lock`() = runTest {
        val env = env() // no managed key, no binding
        val transport = FakeVpnTransport()
        val controller = controller(env, transport)
        val holdL = CompletableDeferred<Unit>()
        val lHeld = CompletableDeferred<Unit>()
        backgroundScope.launch { env.guard.lifecycle.withLock { lHeld.complete(Unit); holdL.await() } }
        lHeld.await()

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                transport, TransportKind.AMNEZIA_WG,
                endpointId = EndpointId("private-gateway"),
                privateKeyRepository = FakeClientKeyRepository(privateKey = KeyPair().privateKey.toBase64()),
            ),
        )
        runCurrent()

        assertEquals("PRIVATE must connect while L is held by someone else", 1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
        holdL.complete(Unit)
    }

    @Test
    fun `Shadowsocks stays available when the managed AWG binding is missing`() = runTest {
        val env = env()
        val awg = FakeVpnTransport()
        val ss = FakeVpnTransport(kind = TransportKind.SHADOWSOCKS_2022)
        val controller = controller(env, awg, shadowsocks = ss)

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                ss, TransportKind.SHADOWSOCKS_2022,
                endpointTransportBinding = EndpointTransportBinding(kind = TransportKind.SHADOWSOCKS_2022, host = "152.70.43.1", port = 28388)
                    .withShadowsocks2022Profile(Shadowsocks2022Profile("2022-blake3-aes-256-gcm")),
            ),
        )
        runCurrent()

        assertEquals(1, ss.connectCallCount)
        assertEquals(0, awg.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `Hysteria2 stays available when the managed AWG binding is unreadable`() = runTest {
        val env = env()
        File(env.dir, "managed_awg_binding.bin").writeBytes(ByteArray(24) { 7 })
        val awg = FakeVpnTransport()
        val hy2 = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        val controller = controller(env, awg, hysteria2 = hy2)

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                hy2, TransportKind.HYSTERIA2,
                endpointId = EndpointId("stockholm"),
                endpointTransportBinding = EndpointTransportBinding(kind = TransportKind.HYSTERIA2, host = "16.170.208.231", port = 443)
                    .withHysteria2Profile(Hysteria2Profile(sni = "origin-sthlm.aknova.pp.ua", obfuscationMode = "NONE")),
            ),
        )
        runCurrent()

        assertEquals(1, hy2.connectCallCount)
        assertEquals(0, awg.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    // --- serialization with identity mutation ---

    @Test
    fun `AWG config build waits for L and sees the mutation made while L was held`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)
        val release = CompletableDeferred<Unit>()
        val lHeld = CompletableDeferred<Unit>()

        // A concurrent identity mutation holds L and invalidates the binding.
        backgroundScope.launch {
            env.guard.lifecycle.withLock {
                lHeld.complete(Unit)
                release.await()
                env.bindings.deleteAll()
            }
        }
        lHeld.await()
        val connectJob = backgroundScope.launch { controller.connect() }
        runCurrent()
        assertEquals("config build must be blocked on L", 0, transport.connectCallCount)

        release.complete(Unit)
        runCurrent()
        connectJob.join()

        assertRefused(transport, controller, diagnostics, "REACTIVATION_REQUIRED")
    }

    @Test
    fun `identity mutation is refused while a connect holds connectMutex`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        transport.connectGate = CompletableDeferred() // connect stays in flight holding connectMutex
        val controller = controller(env, transport)
        val connectJob = backgroundScope.launch { controller.connect() }
        runCurrent()

        var mutated = false
        val result = controller.runManagedIdentityMutation { mutated = true }

        assertEquals(ManagedIdentityMutationResult.Busy, result)
        assertFalse(mutated)
        transport.connectGate!!.complete(Unit)
        connectJob.join()
    }

    @Test
    fun `identity mutation is refused while a session is up and runs under L when idle`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        val controller = controller(env, transport)

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(ManagedIdentityMutationResult.Busy, controller.runManagedIdentityMutation { Unit })

        controller.disconnect()
        runCurrent()
        val result = controller.runManagedIdentityMutation { env.guard.lifecycle.isLocked }
        assertEquals(ManagedIdentityMutationResult.Completed(true), result)
        assertFalse("L must be released afterwards", env.guard.lifecycle.isLocked)
    }

    @Test
    fun `identity mutation releases both locks after an exception`() = runTest {
        val env = env()
        val controller = controller(env)

        val thrown = runCatching { controller.runManagedIdentityMutation<Unit> { throw IllegalStateException("boom") } }

        assertTrue(thrown.exceptionOrNull() is IllegalStateException)
        assertFalse(env.guard.lifecycle.isLocked)
        assertEquals(ManagedIdentityMutationResult.Completed(1), controller.runManagedIdentityMutation { 1 })
    }

    @Test
    fun `cancelled connect waiting on L releases connectMutex and L`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        val controller = controller(env, transport)
        val release = CompletableDeferred<Unit>()
        val lHeld = CompletableDeferred<Unit>()
        val holder = backgroundScope.launch { env.guard.lifecycle.withLock { lHeld.complete(Unit); release.await() } }
        lHeld.await()

        val connectJob = backgroundScope.launch { controller.connect() }
        runCurrent()
        connectJob.cancel()
        connectJob.join()
        release.complete(Unit)
        holder.join()

        assertEquals(0, transport.connectCallCount)
        assertFalse(env.guard.lifecycle.isLocked)
        // connectMutex was released too: an idle mutation can now take it.
        assertEquals(ManagedIdentityMutationResult.Completed(2), controller.runManagedIdentityMutation { 2 })
    }

    // --- reconnect / cached config ---

    @Test
    fun `AWG network recovery reuses the live session and never rebuilds the config`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport() // production AWG kind: IN_PLACE recovery
        val reconnect = FakeReconnectManager()
        val controller = controller(env, transport, reconnectManager = reconnect)
        controller.connect()
        runCurrent()
        val configBefore = transport.lastConfig

        reconnect.triggerNetworkLost()
        runCurrent()
        assertTrue("expected Reconnecting, was ${controller.state.value}", controller.state.value is TransportState.Reconnecting)
        // While recovering, no identity mutation may run against the cached config.
        assertEquals(ManagedIdentityMutationResult.Busy, controller.runManagedIdentityMutation { Unit })

        // Same recovery drive as VpnControllerConnectionOutcomeTest's in-place recovery test.
        reconnect.networkAvailable = true
        advanceTimeBy(5_000)
        runCurrent()

        assertEquals("AWG recovery must not restart the transport", 1, transport.connectCallCount)
        assertTrue("config object must be the original one", configBefore === transport.lastConfig)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `after disconnect the cached config is gone and a new connect re-checks the binding`() = runTest {
        val env = env()
        val publicKey = env.createKey()
        env.bind(ProductionGatewayId.GERMANY, publicKey)
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = controller(env, transport, diagnostics)
        controller.connect()
        runCurrent()
        controller.disconnect()
        runCurrent()

        // Identity mutation through the only supported entry point: binding invalidated.
        val result = controller.runManagedIdentityMutation { env.bindings.deleteAll() }
        assertTrue(result is ManagedIdentityMutationResult.Completed)

        controller.connect()
        runCurrent()

        assertEquals("the second connect must not start AWG", 1, transport.connectCallCount)
        assertRefused0(controller, diagnostics)
    }

    private fun assertRefused0(controller: VpnController, diagnostics: DiagnosticsStore) {
        assertTrue("expected Error, was ${controller.state.value}", controller.state.value is TransportState.Error)
        assertEquals(VpnError.ConfigurationMappingFailure("MANAGED_AWG_REACTIVATION_REQUIRED"), diagnostics.snapshot.value.lastError)
    }
}
