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
import net.pocvpn.client.provisioning.XrayProfileProvisioner
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.XrayTlsProfileProvisioner
import net.pocvpn.client.provisioning.XrayTlsProfileResult
import net.pocvpn.client.provisioning.toXrayProfile
import net.pocvpn.client.provisioning.toXrayTlsProfile
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayProfileRepository
import net.pocvpn.client.vpn.FakeXrayTlsProfileRepository
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
 * B14 - the real self-service Stockholm provisioning path: activateDevice()
 * now takes an explicit targetGatewayId, routes to that gateway's own
 * activation client/Xray provisioners, and requires the response to match
 * the REQUESTED gateway specifically (not merely "some known gateway") -
 * see MainViewModel.activateDevice's own docs.
 */
class MainViewModelStockholmActivationTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun germanySuccess(clientTunnelIp: String = "10.77.0.5") = ProvisioningResult.Success(
        clientTunnelIp = clientTunnelIp,
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun stockholmSuccess(
        clientTunnelIp: String = "10.77.0.2",
        endpointHost: String = ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
        endpointPort: Int = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort,
        gatewayPublicKey: String = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
        gatewayTunnelIp: String = ProductionGatewayCatalog.STOCKHOLM.awg.gatewayTunnelIp,
    ) = ProvisioningResult.Success(
        clientTunnelIp = clientTunnelIp,
        gatewayPublicKey = gatewayPublicKey,
        gatewayTunnelIp = gatewayTunnelIp,
        endpointHost = endpointHost,
        endpointPort = endpointPort,
    )

    private val sampleXrayProfileResult = XrayProfileResult.Success(
        serverAddress = "16.170.208.231", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f", flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )
    private val sampleXrayProfile = sampleXrayProfileResult.toXrayProfile()

    private val sampleXrayTlsProfileResult = XrayTlsProfileResult.Success(
        serverAddress = "16.170.208.231", serverPort = 2083,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "203.0.113.1", fingerprint = "chrome",
    )
    private val sampleXrayTlsProfile = sampleXrayTlsProfileResult.toXrayTlsProfile()

    private class Wiring(
        val identity: FakeClientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        val germanyResult: ProvisioningResult,
        val stockholmResult: ProvisioningResult,
        val stockholmXrayRepo: FakeXrayProfileRepository = FakeXrayProfileRepository(),
        val stockholmXrayTlsRepo: FakeXrayTlsProfileRepository = FakeXrayTlsProfileRepository(),
        val germanyXrayRepo: FakeXrayProfileRepository = FakeXrayProfileRepository(),
    )

    private fun newViewModel(w: Wiring) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = w.identity,
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, _, _ -> w.germanyResult },
        stockholmActivationClient = { _, _, _ -> w.stockholmResult },
        xrayProfileRepository = w.germanyXrayRepo,
        stockholmXrayProfileRepository = w.stockholmXrayRepo,
        stockholmXrayTlsProfileRepository = w.stockholmXrayTlsRepo,
        stockholmXrayProfileProvisioner = XrayProfileProvisioner(
            repository = w.stockholmXrayRepo,
            fetchXrayProfile = { _, _, _ -> sampleXrayProfileResult },
        ),
        stockholmXrayTlsProfileProvisioner = XrayTlsProfileProvisioner(
            repository = w.stockholmXrayTlsRepo,
            fetchXrayTlsProfile = { _, _, _ -> sampleXrayTlsProfileResult },
        ),
        ioDispatcher = testDispatcher,
    )

    private fun activate(viewModel: MainViewModel, credential: String, target: ProductionGatewayId) {
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice(credential, target)
        testDispatcher.scheduler.runCurrent()
    }

    // 1. Germany activation remains valid and unchanged.
    @Test
    fun `Germany activation remains valid and unchanged - defaults to selectedGateway, writes only GERMANY`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w)

        // No explicit target - defaults to selectedGateway.value (GERMANY by default).
        testDispatcher.scheduler.runCurrent()
        viewModel.activateDevice("some-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals("10.77.0.5", w.identity.read(ProductionGatewayId.GERMANY))
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    // 2. Stockholm activation maps only to STOCKHOLM.
    @Test
    fun `Stockholm activation maps only to STOCKHOLM`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertEquals("10.77.0.2", w.identity.read(ProductionGatewayId.STOCKHOLM))
        assertNull(w.identity.read(ProductionGatewayId.GERMANY))
    }

    // 3. Stockholm successful activation writes only STOCKHOLM client identity.
    @Test
    fun `Stockholm successful activation writes only STOCKHOLM client identity - success state`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess(clientTunnelIp = "10.77.0.9"))
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals("10.77.0.9", w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    // 4. Germany identity is not overwritten.
    @Test
    fun `Germany identity is not overwritten by a later Stockholm activation`() = runTest {
        val w = Wiring(
            identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5")),
            germanyResult = germanySuccess(),
            stockholmResult = stockholmSuccess(clientTunnelIp = "10.77.0.2"),
        )
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertEquals("10.77.0.5", w.identity.read(ProductionGatewayId.GERMANY))
        assertEquals("10.77.0.2", w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    // 5. Wrong Stockholm host/key/port/gatewayTunnelIp is rejected.
    @Test
    fun `wrong Stockholm host is rejected - no identity written, Error state`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess(endpointHost = "203.0.113.9"))
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `wrong Stockholm key is rejected`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess(gatewayPublicKey = "not-a-known-key=================="))
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `wrong Stockholm port is rejected`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess(endpointPort = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort + 1))
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `wrong Stockholm gatewayTunnelIp is rejected`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess(gatewayTunnelIp = "10.99.0.1"))
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    // 6. Cross-endpoint response is rejected (matches a DIFFERENT known gateway than requested).
    @Test
    fun `a response that validly matches Germany while STOCKHOLM was requested is rejected - cross-endpoint mismatch`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = germanySuccess())
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Error)
        assertNull(w.identity.read(ProductionGatewayId.STOCKHOLM))
        assertNull(w.identity.read(ProductionGatewayId.GERMANY))
    }

    // 7. Stockholm REALITY profile writes only Stockholm repository.
    @Test
    fun `Stockholm REALITY profile writes only Stockholm's own repository, never Germany's`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertEquals(sampleXrayProfile, w.stockholmXrayRepo.getProfileOrNull())
        assertNull(w.germanyXrayRepo.getProfileOrNull())
    }

    // 8. Stockholm TLS profile writes only Stockholm repository.
    @Test
    fun `Stockholm TLS profile writes only Stockholm's own repository`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w)

        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)

        assertEquals(sampleXrayTlsProfile, w.stockholmXrayTlsRepo.getProfileOrNull())
    }

    // 9. Restart restores provisioned Stockholm readiness correctly.
    @Test
    fun `restart restores provisioned Stockholm readiness - a fresh ViewModel over the same identity store still reports Stockholm provisioned`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w)
        activate(viewModel, "cred", ProductionGatewayId.STOCKHOLM)
        assertEquals("10.77.0.2", w.identity.read(ProductionGatewayId.STOCKHOLM))

        // Simulate app restart: a fresh MainViewModel constructed over the
        // SAME (now-populated) identity store, exactly like the real
        // Factory reconstructing over the same on-disk FileClientTunnelIdentityStore.
        val restarted = newViewModel(Wiring(identity = w.identity, germanyResult = germanySuccess(), stockholmResult = stockholmSuccess()))

        assertTrue(restarted.isGatewayProvisioned(ProductionGatewayId.STOCKHOLM))
        assertEquals(setOf(ProductionGatewayId.STOCKHOLM), restarted.provisionedGatewayIds)
    }

    // 10. Unprovisioned Stockholm remains disabled (regression check for this slice).
    @Test
    fun `unprovisioned Stockholm remains disabled - not selectable, not in provisionedGatewayIds`() = runTest {
        val w = Wiring(germanyResult = germanySuccess(), stockholmResult = stockholmSuccess())
        val viewModel = newViewModel(w) // no activation ever run

        assertTrue(viewModel.provisionedGatewayIds.isEmpty())
        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
    }
}
