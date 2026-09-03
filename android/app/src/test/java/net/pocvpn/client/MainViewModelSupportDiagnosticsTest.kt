@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.support.DiagnosticOutcome
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.PathKind
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.diagnostics.support.buildSupportBundle
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeConnectionOutcomeStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B29 - end-to-end proof, through the real MainViewModel connect flow (not
 * just the isolated recorder), that a real connection attempt produces a
 * sanitized [net.pocvpn.client.diagnostics.support.DiagnosticSession] and
 * that the exported bundle carries no secret material for a real gateway
 * configuration.
 */
class MainViewModelSupportDiagnosticsTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private val configuredGateway = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10",
        endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2",
        gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0", "::/0"),
        profile = AwgProfile.none(),
    )

    private val usableWifi = NetworkProfile(
        type = NetworkType.WIFI, validatedInternet = true, metered = false,
        roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
        vpnActive = false, generation = 1,
    )

    @Test
    fun `a real successful manual connect produces a PROTECTED DIRECT diagnostic session`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, appVersionName = "1.0", appVersionCode = 1L)
        val transport = FakeVpnTransport() // handshakeAvailable defaults to true - a real, immediate Connected/DirectProtected outcome.
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            initialNetworkProfile = usableWifi,
            connectionOutcomeStore = FakeConnectionOutcomeStore(),
            supportDiagnosticsRecorder = recorder,
            supportDiagnosticsStore = store,
            supportDiagnosticsAppVersionName = "1.0",
            supportDiagnosticsAppVersionCode = 1L,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(transport.connectCallCount >= 1)
        val session = viewModel.recentDiagnosticSessions().first()
        assertEquals(DiagnosticOutcome.PROTECTED, session.outcome)
        assertEquals(PathKind.DIRECT, session.selectedPathKind)
        assertEquals(TransportKind.AMNEZIA_WG, session.selectedTransportKind)
        assertEquals("Last connection succeeded", viewModel.lastConnectionResultSummary())
    }

    @Test
    fun `exportSupportBundleJson never leaks the real gateway config's own secret material`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, appVersionName = "1.0", appVersionCode = 1L)
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            initialNetworkProfile = usableWifi,
            connectionOutcomeStore = FakeConnectionOutcomeStore(),
            supportDiagnosticsRecorder = recorder,
            supportDiagnosticsStore = store,
            supportDiagnosticsAppVersionName = "1.0",
            supportDiagnosticsAppVersionCode = 1L,
        )
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        val json = viewModel.exportSupportBundleJson()
        assertFalse(json.contains(configuredGateway.endpointHost))
        assertFalse(json.contains(configuredGateway.serverPublicKeyBase64))
        assertFalse(json.contains(configuredGateway.clientTunnelIp))
    }

    @Test
    fun `clearDiagnosticSessions empties the store, and buildSupportBundle over an empty store is still a valid, tiny bundle`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, appVersionName = "1.0", appVersionCode = 1L)
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            initialNetworkProfile = usableWifi,
            connectionOutcomeStore = FakeConnectionOutcomeStore(),
            supportDiagnosticsRecorder = recorder,
            supportDiagnosticsStore = store,
        )
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.recentDiagnosticSessions().isNotEmpty())

        viewModel.clearDiagnosticSessions()
        assertTrue(viewModel.recentDiagnosticSessions().isEmpty())
        assertEquals("No connection attempts recorded yet", viewModel.lastConnectionResultSummary())
        val bundle = buildSupportBundle(viewModel.recentDiagnosticSessions(), "1.0", 1L, nowEpochMillis = 0L)
        assertTrue(bundle.sessions.isEmpty())
    }
}
