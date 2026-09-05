@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.bootstrap.BootstrapIdentity
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B36 (Phase 4 follow-up) - proves, at the real [MainViewModel] wiring
 * level (not just the pure [net.pocvpn.client.bootstrap.BootstrapActivationOrchestrator]
 * unit tests), that [MainViewModel.activateDeviceViaBootstrap]:
 * - never sends the shared bootstrap identity's OWN public key as the
 *   activation request's device identity - only this device's real,
 *   per-device [net.pocvpn.client.identity.ClientKeyRepository] key ever
 *   appears there, exactly like [MainViewModel.activateDevice] itself
 *   already does. This is the concrete proof that "the bootstrap profile
 *   can never become the normal persisted production profile" - the two
 *   identities never even share a code path that could confuse them.
 * - genuinely reaches [MainViewModel.performActivation] (persistence,
 *   gateway-identity cross-check, all of it) once the fake bootstrap
 *   transport reports a fresh handshake.
 * - skips bootstrap entirely once a gateway is already provisioned.
 */
class MainViewModelBootstrapActivationTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun germanyMatchingSuccess() = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.9",
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun newViewModel(
        identity: FakeClientTunnelIdentityStore,
        result: ProvisioningResult,
        devicePublicKey: String = "device-real-public-key",
        bootstrapTransportFactory: ((ProductionGatewayId) -> VpnTransport)? = { FakeVpnTransport() },
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = devicePublicKey),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = identity,
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, publicKey, _ -> lastActivationPublicKey = publicKey; result },
        stockholmActivationClient = { _, publicKey, _ -> lastActivationPublicKey = publicKey; result },
        ioDispatcher = testDispatcher,
        bootstrapTransportFactory = bootstrapTransportFactory,
    )

    private var lastActivationPublicKey: String? = null

    @Before
    fun resetCapturedKey() {
        lastActivationPublicKey = null
    }

    @Test
    fun `bootstrap-assisted activation sends the device's real public key, never the shared bootstrap identity's key`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = newViewModel(identity, result = germanyMatchingSuccess(), devicePublicKey = "device-real-public-key")

        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDeviceViaBootstrap("real-activation-code")
        testDispatcher.scheduler.runCurrent()

        assertEquals("device-real-public-key", lastActivationPublicKey)
        assertTrue(lastActivationPublicKey != BootstrapIdentity.BOOTSTRAP_PUBLIC_KEY_BASE64)
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals("10.77.0.9", identity.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `bootstrap unavailable when no bootstrap transport factory is wired - never a crash, never a fabricated success`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = newViewModel(
            identity,
            result = germanyMatchingSuccess(),
            bootstrapTransportFactory = null,
        )

        testDispatcher.scheduler.runCurrent()
        viewModel.activateDeviceViaBootstrap("real-activation-code")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.BootstrapUnavailable)
        assertNull(identity.read(ProductionGatewayId.GERMANY))
        assertNull(identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `an already-provisioned device skips bootstrap and uses the normal activation path directly`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        identity.write(ProductionGatewayId.GERMANY, "10.77.0.1") // pre-existing provisioning, default-selected gateway
        // No bootstrap transport wired at all - if bootstrap were attempted
        // (it must not be), this would report BootstrapUnavailable instead.
        val viewModel = newViewModel(identity, result = germanyMatchingSuccess(), bootstrapTransportFactory = null)

        testDispatcher.scheduler.runCurrent()
        viewModel.activateDeviceViaBootstrap("real-activation-code")
        testDispatcher.scheduler.runCurrent()

        // Reached via the normal activateDevice() path (default target = selectedGateway, GERMANY, already provisioned) - proves bootstrap was bypassed entirely, not merely that it happened to succeed.
        assertEquals("10.77.0.9", identity.read(ProductionGatewayId.GERMANY))
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
    }
}
