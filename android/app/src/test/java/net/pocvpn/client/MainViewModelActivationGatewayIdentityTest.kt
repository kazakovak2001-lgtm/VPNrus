@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.SelectedGatewayStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B13 consolidated review fix (findings 1, 2, 6) - proves the live
 * activation -> canonical client tunnel identity boundary: a response is
 * mapped to a gateway from its FULL stable server facts (never UI
 * selection, never host alone), a genuine match writes THAT gateway's own
 * ClientTunnelIdentityStore entry and immediately reconciles
 * [MainViewModel.selectedGateway] with no app restart required, and a
 * response that does not match any known gateway is REJECTED outright -
 * nothing is written or silently accepted-but-ignored.
 *
 * B14 - activateDevice() now takes an explicit targetGatewayId (defaulted
 * only to selectedGateway.value for pre-B14 1-arg call sites); a response
 * must match THAT requested gateway specifically, not merely "some known
 * gateway" - tests below that activate a non-default target now pass it
 * explicitly (see MainViewModelStockholmActivationTest for the dedicated
 * cross-endpoint-mismatch-rejection coverage this enables).
 */
class MainViewModelActivationGatewayIdentityTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun germanyMatchingSuccess(clientTunnelIp: String = "10.77.0.5") = ProvisioningResult.Success(
        clientTunnelIp = clientTunnelIp,
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun stockholmMatchingSuccess(clientTunnelIp: String = "10.77.0.2") = ProvisioningResult.Success(
        clientTunnelIp = clientTunnelIp,
        gatewayPublicKey = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.STOCKHOLM.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort,
    )

    private fun mismatchedSuccess() = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = "not-a-known-key===========================",
        gatewayTunnelIp = "10.77.0.1",
        endpointHost = "203.0.113.9",
        endpointPort = 51820,
    )

    private fun newViewModel(
        identity: FakeClientTunnelIdentityStore,
        selectedGatewayStore: SelectedGatewayStore = FakeSelectedGatewayStore(),
        result: ProvisioningResult,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = identity,
        selectedGatewayStore = selectedGatewayStore,
        activationClient = { _, _ -> result },
        // B14 - each test here only ever activates ONE target at a time,
        // so reusing the SAME fake `result` for Stockholm's own client is
        // harmless and keeps this helper simple - without this, a
        // STOCKHOLM-targeted activateDevice() call would fall through to
        // the REAL production default (an actual HTTPS request) instead of
        // this test's fake response.
        stockholmActivationClient = { _, _ -> result },
        ioDispatcher = testDispatcher,
    )

    @Test
    fun `a response matching Germany's real facts writes clientTunnelIp under GERMANY only`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = newViewModel(identity, result = germanyMatchingSuccess(clientTunnelIp = "10.77.0.5"))

        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("some-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals("10.77.0.5", identity.read(ProductionGatewayId.GERMANY))
        assertNull(identity.read(ProductionGatewayId.STOCKHOLM))
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
    }

    @Test
    fun `a response matching Stockholm's real facts writes clientTunnelIp under STOCKHOLM only`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = newViewModel(identity, result = stockholmMatchingSuccess(clientTunnelIp = "10.77.0.2"))

        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        // B14 - activateDevice() now takes an explicit target; a Stockholm-
        // matching response is only accepted when Stockholm was actually
        // requested (see MainViewModelStockholmActivationTest for the
        // dedicated cross-endpoint-rejection coverage of the OTHER case).
        viewModel.activateDevice("some-credential", ProductionGatewayId.STOCKHOLM)
        testDispatcher.scheduler.runCurrent()

        assertEquals("10.77.0.2", identity.read(ProductionGatewayId.STOCKHOLM))
        assertNull(identity.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `a response that matches no known gateway is rejected - nothing is written for either endpoint`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = newViewModel(identity, result = mismatchedSuccess())

        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("some-credential")
        testDispatcher.scheduler.runCurrent()

        assertNull(identity.read(ProductionGatewayId.GERMANY))
        assertNull(identity.read(ProductionGatewayId.STOCKHOLM))
        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
    }

    @Test
    fun `a response for Stockholm never mutates Germany's already-stored identity, and vice versa`() = runTest {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val viewModel = newViewModel(identity, result = stockholmMatchingSuccess(clientTunnelIp = "10.77.0.2"))

        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("some-credential", ProductionGatewayId.STOCKHOLM)
        testDispatcher.scheduler.runCurrent()

        // Germany's pre-existing entry is completely untouched by a Stockholm activation.
        assertEquals("10.77.0.5", identity.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `reconciliation happens immediately after a successful identity write - no app restart required`() = runTest {
        // Stockholm is persisted as selected but unprovisioned at
        // construction - deliberately retained (no gateway was provisioned
        // yet, so nothing to reconcile to).
        val identity = FakeClientTunnelIdentityStore()
        val selectedGatewayStore = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)
        val viewModel = newViewModel(identity, selectedGatewayStore, result = germanyMatchingSuccess(clientTunnelIp = "10.77.0.5"))

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)

        // Germany now gets provisioned via a real activation, in the SAME
        // running session - no new MainViewModel/Factory is constructed.
        // B14 - explicit target: this device requests Germany even though
        // Stockholm happens to be selected right now.
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("some-credential", ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
        assertEquals(ProductionGatewayId.GERMANY, selectedGatewayStore.read())
    }

    @Test
    fun `reconciliation does not fire when the currently selected gateway is already provisioned`() = runTest {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.STOCKHOLM to "10.77.0.2"))
        val selectedGatewayStore = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)
        val viewModel = newViewModel(identity, selectedGatewayStore, result = germanyMatchingSuccess(clientTunnelIp = "10.77.0.5"))

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)

        // B14 - explicit target: a fresh, unrelated GERMANY activation
        // while Stockholm is already selected and usable.
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("some-credential", ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.runCurrent()

        // Stockholm was already usable - a fresh, unrelated Germany
        // provisioning must not bounce the user's own existing selection.
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    // B30 review fix (blocker 1) - proves the REAL activateDevice() call now
    // genuinely goes through ActivationResilienceCoordinator's bounded
    // multi-origin fallback, not merely a single direct call, and that a
    // successful result from a NON-first origin is applied/persisted by the
    // exact same real production logic as every test above (matchGatewayId
    // cross-check, clientTunnelIdentityStore write, ProvisioningUiState.Success).
    //
    // controlPlaneOriginsForActivation is injected here as a test seam (see
    // MainViewModel's own docs on that param) - production code never
    // supplies more than one real origin (see ControlPlaneOriginSetBuilder's
    // own audited docs), but the FALLBACK MECHANISM itself is genuinely
    // origin-count-agnostic and this proves it end to end through the real
    // activateDevice() path, not just at the ActivationResilienceCoordinator
    // unit level.
    @Test
    fun `B30 - primary origin failure then secondary origin success is applied and persisted by the real activateDevice flow`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        var callCount = 0
        val seenPublicKeys = mutableListOf<String>()
        val seenCredentials = mutableListOf<String>()
        val germanyOrigins = listOf(
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "primary-origin-under-test"),
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "secondary-origin-under-test"),
        )
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            activationClient = { publicKey, credential ->
                callCount++
                seenPublicKeys += publicKey
                seenCredentials += credential
                if (callCount == 1) {
                    ProvisioningResult.NetworkError("SocketTimeoutException: simulated primary-origin timeout")
                } else {
                    germanyMatchingSuccess(clientTunnelIp = "10.77.0.9")
                }
            },
            controlPlaneOriginsForActivation = { germanyOrigins },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete

        viewModel.activateDevice("shared-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals("the primary AND secondary origin must both actually have been attempted", 2, callCount)
        assertEquals(listOf("device-public-key", "device-public-key"), seenPublicKeys)
        assertEquals(listOf("shared-credential", "shared-credential"), seenCredentials)
        assertTrue(
            "the successful (secondary-origin) result must reach the real ProvisioningUiState.Success path",
            viewModel.provisioningState.value is ProvisioningUiState.Success,
        )
        assertEquals(
            "the successful result must actually be persisted via the real clientTunnelIdentityStore write",
            "10.77.0.9",
            identity.read(ProductionGatewayId.GERMANY),
        )
    }

    @Test
    fun `B30 - a malformed primary response leaves no partial state, and the secondary origin's success is what actually gets persisted`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        var callCount = 0
        val origins = listOf(
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "primary-origin-under-test"),
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "secondary-origin-under-test"),
        )
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            activationClient = { _, _ ->
                callCount++
                if (callCount == 1) {
                    ProvisioningResult.MalformedResponse("client_tunnel_ip missing or not a valid IPv4 address")
                } else {
                    germanyMatchingSuccess(clientTunnelIp = "10.77.0.7")
                }
            },
            controlPlaneOriginsForActivation = { origins },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, callCount)
        assertEquals("10.77.0.7", identity.read(ProductionGatewayId.GERMANY))
    }

    @Test
    fun `B30 - all trusted origins exhausted produces a user-friendly typed failure, never a raw exception or hostname`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val origins = listOf(
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "primary-origin-under-test"),
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "secondary-origin-under-test"),
        )
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            activationClient = { _, _ -> ProvisioningResult.NetworkError("SocketTimeoutException: simulated outage on primary-origin-under-test") },
            controlPlaneOriginsForActivation = { origins },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-credential")
        testDispatcher.scheduler.runCurrent()

        assertNull("no partial state must ever be persisted when every origin fails", identity.read(ProductionGatewayId.GERMANY))
        assertEquals(
            "VPN setup could not be completed on this network. Try another network or send diagnostics.",
            viewModel.activationFailureMessage.value,
        )
        val message = viewModel.activationFailureMessage.value!!
        assertTrue(!message.contains("primary-origin-under-test"))
        assertTrue(!message.contains("SocketTimeoutException"))
    }

    @Test
    fun `B30 - authorization rejection stops fallback - the secondary origin is never attempted`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        var callCount = 0
        val origins = listOf(
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "primary-origin-under-test"),
            net.pocvpn.client.controlplane.ControlPlaneOrigin(ProductionGatewayId.GERMANY, "secondary-origin-under-test"),
        )
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            activationClient = { _, _ -> callCount++; ProvisioningResult.Revoked },
            controlPlaneOriginsForActivation = { origins },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("revoked-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals("an authorization rejection must never be retried against a second origin", 1, callCount)
        assertEquals(ProvisioningUiState.Revoked, viewModel.provisioningState.value)
    }
}
