@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayXhttpProfile
import net.pocvpn.client.reachability.CdnClientRuntimeCapabilities
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayXhttpProfileRepository
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test

private val VALID_XHTTP_PROFILE = XrayXhttpProfile(
    server = "edge.aknova.pp.ua",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    xhttpHost = "edge.aknova.pp.ua",
    xhttpPath = "/nova-xhttp/",
    mode = "packet-up",
    uplinkHttpMethod = "POST",
    fingerprint = "chrome",
)

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
 * B62 - proves the transport registry's Direct/EXIT XRAY_XHTTP descriptor is
 * genuinely connected to XrayRuntimeResolver.resolveXhttp's own Ready/
 * Rejected outcome for a given endpoint (never merely "the transport object
 * exists"), is per-endpoint like XRAY_REALITY/TLS_TCP (Germany's profile
 * must never make Stockholm appear available and vice versa), and leaves
 * the SEPARATE CDN/relay XHTTP capability path
 * (cdnRuntimeCapabilities.isPinnedXhttpExecutable()) completely unchanged.
 */
class MainViewModelXrayXhttpEndpointAvailabilityTest {

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
        xrayXhttpProfileRepositories: Map<EndpointId, net.pocvpn.client.identity.XrayXhttpProfileRepository>,
        xrayXhttpTransport: FakeVpnTransport? = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP),
        cdnRuntimeCapabilities: CdnClientRuntimeCapabilities = CdnClientRuntimeCapabilities.unsupported(),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        initialNetworkProfile = USABLE_WIFI,
        xrayXhttpTransport = xrayXhttpTransport,
        xrayXhttpProfileRepositories = xrayXhttpProfileRepositories,
        cdnRuntimeCapabilities = cdnRuntimeCapabilities,
    )

    // --- Case 1: valid Direct EXIT XHTTP profile -> resolver Ready -> AVAILABLE ---

    @Test
    fun `Germany has a real EXIT XHTTP profile - Germany's registry reports AVAILABLE, Stockholm's stays NOT_IMPLEMENTED`() = runTest {
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = mapOf(
                germanyEndpointId to FakeXrayXhttpProfileRepository(VALID_XHTTP_PROFILE),
                stockholmEndpointId to FakeXrayXhttpProfileRepository(profile = null),
            ),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    @Test
    fun `both endpoints have a real EXIT XHTTP profile - both independently report AVAILABLE`() = runTest {
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = mapOf(
                germanyEndpointId to FakeXrayXhttpProfileRepository(VALID_XHTTP_PROFILE),
                stockholmEndpointId to FakeXrayXhttpProfileRepository(VALID_XHTTP_PROFILE),
            ),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    // --- Case 2: no Direct EXIT profile/resolver wired for either endpoint ---

    @Test
    fun `no EXIT XHTTP repository wired for either endpoint - the descriptor exists (transport is wired) but stays NOT_IMPLEMENTED for both`() = runTest {
        val viewModel = newViewModel(xrayXhttpProfileRepositories = emptyMap())
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    @Test
    fun `EXIT XHTTP repositories wired but empty - resolver has nothing to load, registry stays NOT_IMPLEMENTED, never falsely available`() = runTest {
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = mapOf(
                germanyEndpointId to FakeXrayXhttpProfileRepository(profile = null),
                stockholmEndpointId to FakeXrayXhttpProfileRepository(profile = null),
            ),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    // --- Case 3: existing CDN/relay XHTTP path is unchanged ---

    @Test
    fun `CDN relay capability pinned, no EXIT profile - a known CDN ingress endpoint still reports AVAILABLE exactly as before B62`() = runTest {
        val stockholmIngressId = net.pocvpn.client.smartconnect.ProductionIngressEndpoints.STOCKHOLM.id
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = emptyMap(),
            cdnRuntimeCapabilities = CdnClientRuntimeCapabilities.pinnedXhttp(clientVersionCode = 1L),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(stockholmIngressId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    @Test
    fun `CDN relay capability NOT pinned, no EXIT profile - a known CDN ingress endpoint stays NOT_IMPLEMENTED exactly as before B62`() = runTest {
        val stockholmIngressId = net.pocvpn.client.smartconnect.ProductionIngressEndpoints.STOCKHOLM.id
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = emptyMap(),
            cdnRuntimeCapabilities = CdnClientRuntimeCapabilities.unsupported(),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholmIngressId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    @Test
    fun `CDN relay capability pinned but a real EXIT profile also exists elsewhere - the CDN ingress endpoint's own availability still comes from the CDN flag, not the EXIT resolver`() = runTest {
        val stockholmIngressId = net.pocvpn.client.smartconnect.ProductionIngressEndpoints.STOCKHOLM.id
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = mapOf(germanyEndpointId to FakeXrayXhttpProfileRepository(VALID_XHTTP_PROFILE)),
            cdnRuntimeCapabilities = CdnClientRuntimeCapabilities.pinnedXhttp(clientVersionCode = 1L),
        )
        testDispatcher.scheduler.runCurrent()

        // The CDN ingress endpoint is AVAILABLE purely because of the pinned CDN
        // capability - Germany's unrelated EXIT profile must never leak into it.
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(stockholmIngressId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
        // And Germany's own EXIT availability is unaffected by the CDN flag being pinned.
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    // --- Case 4: EXIT resolver's Rejected path must never read as available ---

    @Test
    fun `EXIT XHTTP profile fails validation (Rejected, not Ready) - registry never reports AVAILABLE through the EXIT path`() = runTest {
        // An xhttpPath without a leading slash fails XrayVlessXhttpConfig
        // validation (see XrayVlessXhttpConfigValidationTest), so
        // XrayRuntimeResolver.resolveXhttp returns Rejected, not Ready.
        val invalidProfile = VALID_XHTTP_PROFILE.copy(xhttpPath = "nova-xhttp")
        val viewModel = newViewModel(
            xrayXhttpProfileRepositories = mapOf(germanyEndpointId to FakeXrayXhttpProfileRepository(invalidProfile)),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }

    // --- Not merely "the transport object exists" ---

    @Test
    fun `xrayXhttpTransport is wired but no EXIT profile exists anywhere - stays NOT_IMPLEMENTED, proving availability is not just object presence`() = runTest {
        val viewModel = newViewModel(
            xrayXhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP),
            xrayXhttpProfileRepositories = mapOf(germanyEndpointId to FakeXrayXhttpProfileRepository(profile = null)),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyEndpointId).descriptorFor(TransportKind.XRAY_XHTTP)?.status)
    }
}
