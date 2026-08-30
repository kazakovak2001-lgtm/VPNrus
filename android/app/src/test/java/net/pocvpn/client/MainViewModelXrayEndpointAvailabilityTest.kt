@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.toXrayProfile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayProfileRepository
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

private val SAMPLE_XRAY_PROFILE = XrayProfileResult.Success(
    serverAddress = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
).toXrayProfile()

private val CONFIGURED_GATEWAY = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10", endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
)

private val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
    type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
    roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
    vpnActive = false, generation = 1,
)

/**
 * B13 consolidated review fix (finding 4) - proves XRAY_REALITY/TLS_TCP
 * availability is genuinely per-endpoint: Germany's own profile existing
 * must never make Stockholm appear available (and vice versa), and an AWG
 * -> Xray failover must evaluate/execute against the SAME endpoint the
 * failed AWG attempt actually targeted, never a different one's
 * availability.
 */
class MainViewModelXrayEndpointAvailabilityTest {

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

    private fun newViewModel(
        germanyProfileRepository: net.pocvpn.client.identity.XrayProfileRepository?,
        stockholmProfileRepository: net.pocvpn.client.identity.XrayProfileRepository?,
        xrayTransport: FakeVpnTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY),
        awgTransport: FakeVpnTransport = FakeVpnTransport(),
        identity: FakeClientTunnelIdentityStore = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2")
        ),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = awgTransport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        initialNetworkProfile = USABLE_WIFI,
        xrayTransport = xrayTransport,
        xrayProfileRepository = germanyProfileRepository,
        stockholmXrayProfileRepository = stockholmProfileRepository,
        clientTunnelIdentityStore = identity,
    )

    @Test
    fun `Germany Xray only - Germany's registry reports AVAILABLE, Stockholm's stays NOT_IMPLEMENTED`() = runTest {
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
            stockholmProfileRepository = FakeXrayProfileRepository(profile = null),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    @Test
    fun `Stockholm Xray only - Stockholm's registry reports AVAILABLE, Germany's stays NOT_IMPLEMENTED`() = runTest {
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(profile = null),
            stockholmProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    @Test
    fun `both provisioned - both endpoints independently report AVAILABLE`() = runTest {
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
            stockholmProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    @Test
    fun `neither provisioned - both endpoints report NOT_IMPLEMENTED`() = runTest {
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(profile = null),
            stockholmProfileRepository = FakeXrayProfileRepository(profile = null),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    @Test
    fun `no Xray repository wired for either endpoint - the descriptor exists (xrayTransport is wired) but stays NOT_IMPLEMENTED for both`() = runTest {
        val viewModel = newViewModel(germanyProfileRepository = null, stockholmProfileRepository = null)
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    @Test
    fun `failover targeting Stockholm never uses Germany's Xray availability - AWG fails, Stockholm has no profile, no fallback`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
            stockholmProfileRepository = FakeXrayProfileRepository(profile = null),
            xrayTransport = xrayTransport,
            awgTransport = awgTransport,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        // No Xray fallback: even though GERMANY has a real profile, THIS
        // attempt targets Stockholm, which has none - Germany's own
        // availability must never leak in.
        assertEquals(0, xrayTransport.connectCallCount)
        assert(viewModel.transportState.value !is TransportState.Connected) {
            "expected no successful fallback, got ${viewModel.transportState.value}"
        }
    }

    @Test
    fun `failover targeting Stockholm succeeds when Stockholm itself has a real profile - genuinely endpoint-scoped, not just always-blocked`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(profile = null),
            stockholmProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
            xrayTransport = xrayTransport,
            awgTransport = awgTransport,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(TransportState.Connected, viewModel.transportState.value)
    }

    @Test
    fun `failover targeting Germany never uses Stockholm's Xray availability - AWG fails, Germany has no profile, no fallback`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = newViewModel(
            germanyProfileRepository = FakeXrayProfileRepository(profile = null),
            stockholmProfileRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE),
            xrayTransport = xrayTransport,
            awgTransport = awgTransport,
        )
        testDispatcher.scheduler.runCurrent()

        // Germany is the default selection - never call selectGateway.
        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assert(viewModel.transportState.value !is TransportState.Connected) {
            "expected no successful fallback, got ${viewModel.transportState.value}"
        }
    }
}
