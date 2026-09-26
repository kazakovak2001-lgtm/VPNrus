@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayXhttpProfile
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.provisioning.XrayXhttpProfileProvisioner
import net.pocvpn.client.provisioning.XrayXhttpProfileResult
import net.pocvpn.client.provisioning.toXrayXhttpProfile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayXhttpProfileRepository
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
 * B64 - proves activateDevice() actually provisions a real Direct/EXIT
 * XHTTP profile end to end: fetch -> strict validation -> persistence into
 * the endpoint-specific repository -> xrayXhttpAvailableEndpoints only on a
 * genuine, re-derived Ready resolution (never merely because provisioning
 * was attempted, never merely because the wire call reported Saved).
 * Mirrors [MainViewModelStockholmActivationTest]'s own per-endpoint
 * isolation discipline.
 */
class MainViewModelXrayXhttpActivationTest {

    private val testDispatcher = StandardTestDispatcher()
    private val germanyEndpointId = ProductionGatewayCatalog.GERMANY.endpointId
    private val stockholmEndpointId = ProductionGatewayCatalog.STOCKHOLM.endpointId

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun germanySuccess() = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun stockholmSuccess() = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.2",
        gatewayPublicKey = ProductionGatewayCatalog.STOCKHOLM.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.STOCKHOLM.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.STOCKHOLM.awg.endpointPort,
    )

    private val sampleXhttpResult = XrayXhttpProfileResult.Success(
        serverAddress = "edge.aknova.pp.ua",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        xhttpHost = "edge.aknova.pp.ua",
        xhttpPath = "/nova-xhttp/",
        mode = "packet-up",
        uplinkHttpMethod = "POST",
        fingerprint = "chrome",
    )
    private val sampleXhttpProfile = sampleXhttpResult.toXrayXhttpProfile()

    private class Wiring(
        val identity: FakeClientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        val germanyXhttpRepo: FakeXrayXhttpProfileRepository = FakeXrayXhttpProfileRepository(),
        val stockholmXhttpRepo: FakeXrayXhttpProfileRepository = FakeXrayXhttpProfileRepository(),
        val stockholmFetchResult: XrayXhttpProfileResult = XrayXhttpProfileResult.ServiceUnavailable,
    )

    private fun newViewModel(w: Wiring) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = w.identity,
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, _, _ -> germanySuccess() },
        stockholmActivationClient = { _, _, _ -> stockholmSuccess() },
        xrayXhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP),
        xrayXhttpProfileRepositories = mapOf(
            germanyEndpointId to w.germanyXhttpRepo,
            stockholmEndpointId to w.stockholmXhttpRepo,
        ),
        xrayXhttpProfileProvisioners = mapOf(
            germanyEndpointId to XrayXhttpProfileProvisioner(
                repository = w.germanyXhttpRepo,
                gatewayId = ProductionGatewayId.GERMANY,
                fetchXrayXhttpProfile = { _, _, _ -> sampleXhttpResult },
            ),
            stockholmEndpointId to XrayXhttpProfileProvisioner(
                repository = w.stockholmXhttpRepo,
                gatewayId = ProductionGatewayId.STOCKHOLM,
                fetchXrayXhttpProfile = { _, _, _ -> w.stockholmFetchResult },
            ),
        ),
        ioDispatcher = testDispatcher,
    )

    private fun activate(viewModel: MainViewModel, target: ProductionGatewayId) {
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete
        viewModel.activateDevice("cred", target)
        testDispatcher.scheduler.runCurrent()
    }

    // --- Case 10: successful provisioning persists the profile ---

    @Test
    fun `successful Germany activation persists the real EXIT XHTTP profile into Germany's own repository`() = runTest {
        val w = Wiring()
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.GERMANY)

        assertEquals(sampleXhttpProfile, w.germanyXhttpRepo.getProfileOrNull())
    }

    // --- Case 13: activation for one gateway never populates another's repository ---

    @Test
    fun `Germany activation never populates Stockholm's own EXIT XHTTP repository`() = runTest {
        val w = Wiring()
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.GERMANY)

        assertNull(w.stockholmXhttpRepo.getProfileOrNull())
    }

    @Test
    fun `Stockholm activation never populates Germany's own EXIT XHTTP repository`() = runTest {
        val w = Wiring(stockholmFetchResult = sampleXhttpResult)
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.STOCKHOLM)

        assertEquals(sampleXhttpProfile, w.stockholmXhttpRepo.getProfileOrNull())
        assertNull(w.germanyXhttpRepo.getProfileOrNull())
    }

    // --- Case 12: successful provisioning updates xrayXhttpAvailableEndpoints (via the registry) ---

    @Test
    fun `successful Germany EXIT XHTTP provisioning makes the registry report AVAILABLE for Germany`() = runTest {
        val w = Wiring()
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.GERMANY)

        assertEquals(
            TransportStatus.AVAILABLE,
            viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }

    @Test
    fun `successful Germany EXIT XHTTP provisioning never makes Stockholm's own registry entry AVAILABLE`() = runTest {
        val w = Wiring()
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.GERMANY)

        assertEquals(
            TransportStatus.NOT_IMPLEMENTED,
            viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }

    // --- Case 11: failed provisioning never marks the endpoint available ---

    @Test
    fun `provisioning rejected as ServiceUnavailable never marks Stockholm's registry entry available`() = runTest {
        val w = Wiring(stockholmFetchResult = XrayXhttpProfileResult.ServiceUnavailable)
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.STOCKHOLM)

        assertNull(w.stockholmXhttpRepo.getProfileOrNull())
        assertEquals(
            TransportStatus.NOT_IMPLEMENTED,
            viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }

    @Test
    fun `provisioning rejected as Unauthorized never persists a profile or marks the endpoint available`() = runTest {
        val w = Wiring(stockholmFetchResult = XrayXhttpProfileResult.Unauthorized)
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.STOCKHOLM)

        assertNull(w.stockholmXhttpRepo.getProfileOrNull())
        assertEquals(
            TransportStatus.NOT_IMPLEMENTED,
            viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }

    @Test
    fun `a malformed response is never saved and never marks the endpoint available`() = runTest {
        val w = Wiring(stockholmFetchResult = XrayXhttpProfileResult.MalformedResponse("mode is not a recognized value"))
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.STOCKHOLM)

        assertNull(w.stockholmXhttpRepo.getProfileOrNull())
        assertEquals(
            TransportStatus.NOT_IMPLEMENTED,
            viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }

    // AWG activation success is completely unaffected by XHTTP provisioning's own outcome either way.

    @Test
    fun `AWG activation succeeds regardless of the EXIT XHTTP provisioning outcome`() = runTest {
        val w = Wiring(stockholmFetchResult = XrayXhttpProfileResult.ServiceUnavailable)
        val viewModel = newViewModel(w)

        activate(viewModel, ProductionGatewayId.STOCKHOLM)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals("10.77.0.2", w.identity.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `no EXIT XHTTP provisioner wired for a gateway - activation still succeeds, registry stays NOT_IMPLEMENTED`() = runTest {
        val identity = FakeClientTunnelIdentityStore()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            selectedGatewayStore = FakeSelectedGatewayStore(),
            activationClient = { _, _, _ -> germanySuccess() },
            xrayXhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP),
            // No xrayXhttpProfileRepositories/xrayXhttpProfileProvisioners wired at all.
            ioDispatcher = testDispatcher,
        )

        activate(viewModel, ProductionGatewayId.GERMANY)

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals("10.77.0.5", identity.read(ProductionGatewayId.GERMANY))
        assertEquals(
            TransportStatus.NOT_IMPLEMENTED,
            viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status,
        )
    }
}
