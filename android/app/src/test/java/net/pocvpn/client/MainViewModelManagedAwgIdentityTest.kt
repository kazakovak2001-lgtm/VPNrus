@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.AwgClientKeyRepository
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileIdentityStore
import net.pocvpn.client.identity.FileManagedAwgBindingStore
import net.pocvpn.client.identity.ManagedAwgBindingDeleteResult
import net.pocvpn.client.identity.ManagedAwgBindingLoadResult
import net.pocvpn.client.identity.ManagedAwgBindingRemoveResult
import net.pocvpn.client.identity.ManagedAwgBindingStore
import net.pocvpn.client.identity.ManagedAwgBindingUpdateResult
import net.pocvpn.client.identity.ManagedAwgEligibility
import net.pocvpn.client.identity.ManagedAwgEligibilityReason
import net.pocvpn.client.identity.ManagedAwgIdentityGuard
import net.pocvpn.client.identity.ManagedAwgKeyFingerprint
import net.pocvpn.client.identity.ManagedIdentityLifecycle
import net.pocvpn.client.identity.ManagedKeyPeek
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.ProfileLoadResult
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/** Phase B step 2 - activation commit and identity regeneration through the shared guard. */
class MainViewModelManagedAwgIdentityTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(testDispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private val germanyActivation = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.2",
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    /** Delegating store that records what was already persisted at the moment of each call. */
    private class RecordingStore(
        private val delegate: ManagedAwgBindingStore,
        private val onUpdate: () -> Unit = {},
        private val onDelete: suspend () -> Unit = {},
        private val failUpdate: Boolean = false,
        private val failDelete: Boolean = false,
        private val failRemove: Boolean = false,
    ) : ManagedAwgBindingStore by delegate {
        override suspend fun removeGateway(gatewayId: ProductionGatewayId): ManagedAwgBindingRemoveResult {
            if (failRemove) return ManagedAwgBindingRemoveResult.WriteFailed("simulated")
            return delegate.removeGateway(gatewayId)
        }

        override suspend fun updateGateway(
            gatewayId: ProductionGatewayId,
            activationFingerprint: String,
            currentKey: suspend () -> ManagedKeyPeek,
        ): ManagedAwgBindingUpdateResult {
            onUpdate()
            if (failUpdate) return ManagedAwgBindingUpdateResult.WriteFailed("simulated")
            return delegate.updateGateway(gatewayId, activationFingerprint, currentKey)
        }

        override suspend fun deleteAll(): ManagedAwgBindingDeleteResult {
            onDelete()
            if (failDelete) return ManagedAwgBindingDeleteResult.Failed("simulated")
            return delegate.deleteAll()
        }
    }

    private inner class Env {
        val dir: File = tmp.newFolder()
        val repo = AwgClientKeyRepository(FileIdentityStore(dir), FakeAesGcmKeyEncryptor())
        val fileBindings = FileManagedAwgBindingStore(dir)
        val tunnels = FileClientTunnelIdentityStore(dir)
        val profiles = FileProfileStore(dir)

        fun viewModel(
            bindings: ManagedAwgBindingStore = fileBindings,
            activation: (String) -> ProvisioningResult = { germanyActivation },
            profileStore: net.pocvpn.client.vpn.config.ProfileStore = profiles,
        ): Pair<MainViewModel, ManagedAwgIdentityGuard> {
            val guard = ManagedAwgIdentityGuard(ManagedIdentityLifecycle(), bindings, tunnels::read)
            val vm = MainViewModel(
                clientKeyRepository = repo,
                transport = FakeVpnTransport(),
                gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
                reconnectManager = FakeReconnectManager(),
                diagnosticsStore = DiagnosticsStore(),
                clientTunnelIdentityStore = tunnels,
                profileStore = profileStore,
                activationClient = { _, publicKey, _ -> activation(publicKey) },
                ioDispatcher = testDispatcher,
                managedAwgIdentityGuard = guard,
            )
            testDispatcher.scheduler.runCurrent() // init creates the key under L
            return vm to guard
        }

        fun currentPublicKey(): String = runBlocking { repo.getPublicKey() }
    }

    private fun eligibility(env: Env, gateway: ProductionGatewayId = ProductionGatewayId.GERMANY) = runBlocking {
        ManagedAwgEligibility.evaluate(gateway, false, env.fileBindings.read(), env.repo.peekPublicKey())
    }

    // --- activation commit ---

    @Test
    fun `unchanged key commits profile and tunnel IP first and the binding last`() = runTest {
        val env = Env()
        var tunnelIpAtBindingTime: String? = "unset"
        var profileAtBindingTime: Any? = null
        val store = RecordingStore(env.fileBindings, onUpdate = {
            tunnelIpAtBindingTime = env.tunnels.read(ProductionGatewayId.GERMANY)
            profileAtBindingTime = env.profiles.read()
        })
        val (vm, _) = env.viewModel(bindings = store)
        val sentKey = env.currentPublicKey()

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.COMMITTED, vm.lastManagedActivationCommitOutcome)
        assertEquals("10.77.0.2", tunnelIpAtBindingTime)
        assertTrue(profileAtBindingTime is ProfileLoadResult.Found)
        assertEquals(
            ManagedAwgBindingLoadResult.Valid(mapOf(ProductionGatewayId.GERMANY to ManagedAwgKeyFingerprint.of(sentKey))),
            env.fileBindings.read(),
        )
        assertEquals(ManagedAwgEligibilityReason.AWG_ACTIVE, eligibility(env))
        assertTrue(vm.provisioningState.value is ProvisioningUiState.Success)
    }

    @Test
    fun `key changed while activation was in flight writes no profile, IP or binding`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(activation = {
            // Simulates an identity replacement racing the HTTP request.
            runBlocking { env.repo.clearIdentity(); env.repo.getOrCreateIdentity() }
            germanyActivation
        })

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.KEY_CHANGED_DURING_ACTIVATION, vm.lastManagedActivationCommitOutcome)
        assertNull(env.tunnels.read(ProductionGatewayId.GERMANY))
        assertTrue(env.profiles.read() is ProfileLoadResult.NotFound)
        assertEquals(ManagedAwgBindingLoadResult.Absent, env.fileBindings.read())
        val state = vm.provisioningState.value
        assertTrue(state is ProvisioningUiState.Error && state.message.startsWith("KEY_CHANGED_DURING_ACTIVATION"))
    }

    @Test
    fun `binding write failure after server acceptance is explicit and AWG stays blocked`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(bindings = RecordingStore(env.fileBindings, failUpdate = true))

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.SERVER_ACCEPTED_LOCAL_COMMIT_FAILED, vm.lastManagedActivationCommitOutcome)
        assertEquals("10.77.0.2", env.tunnels.read(ProductionGatewayId.GERMANY)) // written before the binding
        assertEquals(ManagedAwgBindingLoadResult.Absent, env.fileBindings.read())
        assertEquals(ManagedAwgEligibilityReason.REACTIVATION_REQUIRED, eligibility(env))
        val state = vm.provisioningState.value
        assertTrue(state is ProvisioningUiState.Error && state.message.startsWith("SERVER_ACCEPTED_LOCAL_COMMIT_FAILED"))
    }

    @Test
    fun `DEVICE_LIMIT from the server changes nothing locally`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(activation = { ProvisioningResult.DeviceLimitReached })

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProvisioningUiState.DeviceLimitReached, vm.provisioningState.value)
        assertNull(vm.lastManagedActivationCommitOutcome)
        assertNull(env.tunnels.read(ProductionGatewayId.GERMANY))
        assertEquals(ManagedAwgBindingLoadResult.Absent, env.fileBindings.read())
    }

    @Test
    fun `legacy install with a tunnel IP but no binding requires reactivation`() = runTest {
        val env = Env()
        env.tunnels.write(ProductionGatewayId.GERMANY, "10.77.0.4")
        env.viewModel()

        assertEquals("10.77.0.4", env.tunnels.read(ProductionGatewayId.GERMANY)) // not deleted
        assertEquals(ManagedAwgBindingLoadResult.Absent, env.fileBindings.read()) // not adopted
        assertEquals(ManagedAwgEligibilityReason.REACTIVATION_REQUIRED, eligibility(env))
    }

    // --- A-1: re-activation of an already bound gateway ---

    private fun bindCurrent(env: Env, vararg gateways: ProductionGatewayId) = runBlocking {
        val key = env.repo.getPublicKey()
        gateways.forEach { env.fileBindings.updateGateway(it, ManagedAwgKeyFingerprint.of(key)) { ManagedKeyPeek.Present(key) } }
    }

    @Test
    fun `reactivation whose new binding write fails leaves the gateway ineligible and other gateways untouched`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(bindings = RecordingStore(env.fileBindings, failUpdate = true))
        bindCurrent(env, ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM)
        assertEquals(ManagedAwgEligibilityReason.AWG_ACTIVE, eligibility(env))

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.SERVER_ACCEPTED_LOCAL_COMMIT_FAILED, vm.lastManagedActivationCommitOutcome)
        assertEquals(ManagedAwgEligibilityReason.REACTIVATION_REQUIRED, eligibility(env, ProductionGatewayId.GERMANY))
        assertEquals(ManagedAwgEligibilityReason.AWG_ACTIVE, eligibility(env, ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `profile write failure after invalidation keeps the gateway ineligible and the tunnel IP unchanged`() = runTest {
        val env = Env()
        val failingProfiles = object : net.pocvpn.client.vpn.config.ProfileStore {
            override fun read(): ProfileLoadResult = ProfileLoadResult.NotFound
            override fun write(profile: net.pocvpn.client.vpn.config.PersistedProfile) = throw java.io.IOException("simulated")
            override fun delete() = Unit
        }
        val (vm, _) = env.viewModel(profileStore = failingProfiles)
        bindCurrent(env, ProductionGatewayId.GERMANY)
        env.tunnels.write(ProductionGatewayId.GERMANY, "10.77.0.9")

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.SERVER_ACCEPTED_LOCAL_COMMIT_FAILED, vm.lastManagedActivationCommitOutcome)
        assertEquals("10.77.0.9", env.tunnels.read(ProductionGatewayId.GERMANY)) // not advanced to 10.77.0.2
        assertEquals(ManagedAwgEligibilityReason.REACTIVATION_REQUIRED, eligibility(env))
    }

    @Test
    fun `failed invalidation aborts the commit before any profile or tunnel IP write`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(bindings = RecordingStore(env.fileBindings, failRemove = true))
        bindCurrent(env, ProductionGatewayId.GERMANY)
        env.tunnels.write(ProductionGatewayId.GERMANY, "10.77.0.9")
        val bindingsBefore = runBlocking { env.fileBindings.read() }

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.SERVER_ACCEPTED_LOCAL_COMMIT_FAILED, vm.lastManagedActivationCommitOutcome)
        assertTrue(env.profiles.read() is ProfileLoadResult.NotFound)
        assertEquals("10.77.0.9", env.tunnels.read(ProductionGatewayId.GERMANY))
        // The previous, internally consistent state is left exactly as it was.
        assertEquals(bindingsBefore, runBlocking { env.fileBindings.read() })
        val state = vm.provisioningState.value
        assertTrue(state is ProvisioningUiState.Error && state.message.startsWith("SERVER_ACCEPTED_LOCAL_COMMIT_FAILED"))
    }

    @Test
    fun `successful reactivation with the same key re-binds the gateway`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel()
        bindCurrent(env, ProductionGatewayId.GERMANY)
        env.tunnels.write(ProductionGatewayId.GERMANY, "10.77.0.9")

        vm.activateDevice("credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(ManagedActivationCommitOutcome.COMMITTED, vm.lastManagedActivationCommitOutcome)
        assertEquals("10.77.0.2", env.tunnels.read(ProductionGatewayId.GERMANY))
        assertEquals(ManagedAwgEligibilityReason.AWG_ACTIVE, eligibility(env))
    }

    // --- identity regeneration ---

    @Test
    fun `regeneration deletes bindings before the key is replaced`() = runTest {
        val env = Env()
        var keyAtDeleteTime: ManagedKeyPeek? = null
        val store = RecordingStore(env.fileBindings, onDelete = { keyAtDeleteTime = env.repo.peekPublicKey() })
        val (vm, _) = env.viewModel(bindings = store)
        val oldKey = env.currentPublicKey()
        env.fileBindings.updateGateway(ProductionGatewayId.GERMANY, ManagedAwgKeyFingerprint.of(oldKey)) { ManagedKeyPeek.Present(oldKey) }

        val result = vm.regenerateManagedIdentity()

        assertEquals(ManagedIdentityRegenerationResult.REGENERATED, result)
        assertEquals(ManagedKeyPeek.Present(oldKey), keyAtDeleteTime)
        assertEquals(ManagedAwgBindingLoadResult.Absent, env.fileBindings.read())
        assertNotEquals(oldKey, env.currentPublicKey())
        assertEquals(env.currentPublicKey(), vm.publicKey.value)
    }

    @Test
    fun `binding invalidation failure leaves the key and bindings untouched`() = runTest {
        val env = Env()
        val (vm, _) = env.viewModel(bindings = RecordingStore(env.fileBindings, failDelete = true))
        val oldKey = env.currentPublicKey()
        env.fileBindings.updateGateway(ProductionGatewayId.GERMANY, ManagedAwgKeyFingerprint.of(oldKey)) { ManagedKeyPeek.Present(oldKey) }
        val before = env.fileBindings.read()

        val result = vm.regenerateManagedIdentity()

        assertEquals(ManagedIdentityRegenerationResult.BINDING_INVALIDATION_FAILED, result)
        assertEquals(oldKey, env.currentPublicKey())
        assertEquals(before, env.fileBindings.read())
        assertEquals(ManagedAwgEligibilityReason.AWG_ACTIVE, eligibility(env))
    }
}
