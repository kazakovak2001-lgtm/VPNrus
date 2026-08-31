@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import android.content.Intent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
    type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
    roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
    vpnActive = false, generation = 1,
)

private val bothProvisioned = FakeClientTunnelIdentityStore(
    mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
)

/** In-memory GatewayAutoModeStore double - mirrors FakeSelectedGatewayStore's own shape. */
private class FakeGatewayAutoModeStore(initial: Boolean = false) : GatewayAutoModeStore {
    var current: Boolean = initial
        private set
    var writeCallCount = 0
        private set

    override fun read(): Boolean = current
    override fun write(auto: Boolean) {
        writeCallCount++
        current = auto
    }
}

/**
 * B16 - a deterministic AWG transport double for cross-gateway failover
 * tests: fails (VpnError.BackendStartFailure, via a thrown exception in
 * connect() - the SAME real path VpnController.doConnectAttempt's catch
 * block already handles) for its first [failFirstNCalls] invocations, then
 * succeeds. Avoids depending on VpnController's real-time handshake-timeout
 * polling loop (see FakeVpnTransport.handshakeAvailable's own docs) so the
 * test needs no wall-clock/dispatcher time advancement to observe a
 * terminal failure.
 */
private class FailNTimesThenSucceedTransport(private val failFirstNCalls: Int) : VpnTransport {
    override val name: String = "fail-n-then-succeed"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    var disconnectCallCount = 0
        private set

    override fun preparePermissionIntent(): Intent? = null

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        // B16 test note - deliberately does NOT write TransportState.Connecting
        // to [stateFlow] before a simulated failure: VpnController's own
        // background collector (switchActiveTransport) forwards every
        // post-hasTouchedTransport emission from this flow, and since this
        // fake never actually suspends, a transient "Connecting" write here
        // would otherwise be delivered to that collector AFTER
        // doConnectAttempt's own authoritative catch-block setState(Error) -
        // clobbering it back to Connecting. A real transport's own state
        // machine does not exhibit this artifact because its emissions are
        // driven by genuine async backend events, not a synchronous throw.
        if (connectCallCount <= failFirstNCalls) {
            throw RuntimeException("simulated backend start failure")
        }
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        disconnectCallCount++
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

/**
 * B16 - proves the real architecture implemented for automatic multi-gateway
 * selection/failover: candidate construction across every provisioned
 * gateway, manual-mode isolation, bounded cross-gateway failover, fail-
 * closed exhaustion, and persisted mode restart-durability.
 */
class MainViewModelAutoGatewayTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newViewModel(
        transport: VpnTransport = FakeVpnTransport(),
        autoModeStore: GatewayAutoModeStore = FakeGatewayAutoModeStore(),
        identityStore: net.pocvpn.client.vpn.config.ClientTunnelIdentityStore = bothProvisioned,
        selectedGatewayStore: net.pocvpn.client.vpn.config.SelectedGatewayStore = FakeSelectedGatewayStore(),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = selectedGatewayStore,
        clientTunnelIdentityStore = identityStore,
        gatewayAutoModeStore = autoModeStore,
        initialNetworkProfile = USABLE_WIFI,
    )

    // --- candidate construction ---

    @Test
    fun `auto candidates cover both Germany and Stockholm when both are provisioned`() {
        val viewModel = newViewModel()
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), candidates.map { it.gatewayId }.toSet())
    }

    @Test
    fun `unprovisioned gateway is excluded from auto candidates`() {
        val viewModel = newViewModel(identityStore = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5")))
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    @Test
    fun `neither gateway provisioned - connect() in auto mode fails closed without ever calling the transport`() = runTest {
        val transport = FakeVpnTransport()
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore, identityStore = FakeClientTunnelIdentityStore())

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
    }

    // --- mode persistence ---

    @Test
    fun `setGatewayAutoMode persists and survives a fresh ViewModel, simulating app restart`() {
        val store = FakeGatewayAutoModeStore()
        val viewModel = newViewModel(autoModeStore = store)

        viewModel.setGatewayAutoMode(true)
        assertTrue(viewModel.gatewayAutoMode.value)

        val restarted = newViewModel(autoModeStore = store)
        assertTrue(restarted.gatewayAutoMode.value)
    }

    @Test
    fun `manually selecting a gateway exits automatic mode - manual selection stays deterministic`() {
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(autoModeStore = autoStore)
        assertTrue(viewModel.gatewayAutoMode.value)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(false, viewModel.gatewayAutoMode.value)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    // --- manual mode never cross-fails ---

    @Test
    fun `manual Germany - an AWG failure never advances to Stockholm`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.GERMANY)
        val viewModel = newViewModel(transport, selectedGatewayStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
        assertEquals(ProductionGatewayId.GERMANY, viewModel.activeGatewayId.value)
        assertNull(viewModel.autoGatewayDiagnostics.value)
    }

    @Test
    fun `manual Stockholm - an AWG failure never advances to Germany`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)
        val viewModel = newViewModel(transport, selectedGatewayStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.activeGatewayId.value)
    }

    // --- automatic cross-gateway failover ---

    @Test
    fun `auto mode - first candidate fails, second candidate connects - exactly two distinct attempts, bounded`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 1)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(2, candidates.size)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        val diagnostics = viewModel.autoGatewayDiagnostics.value!!
        assertEquals(2, diagnostics.attempted.size)
        assertEquals(diagnostics.attempted.map { it.gatewayId }.toSet(), diagnostics.attempted.map { it.gatewayId }.distinct().toSet())
        assertEquals(diagnostics.attempted.last().gatewayId, viewModel.activeGatewayId.value)
        assertEquals(false, diagnostics.exhausted)
    }

    @Test
    fun `auto mode - both candidates fail - fails closed, never retries a candidate, never loops forever`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // Exactly 2 real, distinct (gateway, transport) attempts - the full
        // provisioned candidate set, never re-attempted, never an unbounded loop.
        assertEquals(2, transport.connectCallCount)
        val diagnostics = viewModel.autoGatewayDiagnostics.value!!
        assertEquals(2, diagnostics.attempted.size)
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), diagnostics.attempted.map { it.gatewayId }.toSet())
        assertTrue(diagnostics.exhausted)
    }

    @Test
    fun `auto mode - immediate success on the top-ranked candidate needs exactly one attempt`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 0)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(1, viewModel.autoGatewayDiagnostics.value?.attempted?.size)
    }

    // --- B16 consolidated review fix (Blocker 1): pinned candidate config is immutable for the attempt ---

    @Test
    fun `auto candidate config is pinned - mutating ClientTunnelIdentityStore after resolve does not change the executed tunnel`() = runTest {
        val transport = FakeVpnTransport(permission = android.content.Intent())
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        )
        val viewModel = newViewModel(transport, autoStore, identity)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        // A VPN permission prompt is pending - no real attempt executed yet.
        assertEquals(0, transport.connectCallCount)

        // Mutate the SAME identity-store instance the candidate was already
        // ranked/pinned from, simulating this device's provisioning changing
        // in the gap while the user is responding to the system prompt.
        identity.write(ProductionGatewayId.GERMANY, "10.99.99.99")

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        val sent = (transport.lastConfig as net.pocvpn.client.vpn.config.TransportConfig.Awg).config
        // The pinned candidate's ORIGINAL client tunnel IP ("10.77.0.5",
        // captured when the candidate was ranked/resolved), never the
        // mutated value the identity store holds now.
        assertEquals(listOf("10.77.0.5/32"), sent.localAddresses)
    }
}
