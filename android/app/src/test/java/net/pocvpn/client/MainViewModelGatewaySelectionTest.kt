@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.SelectedGatewayStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B13 - proves MainViewModel's real, user-facing gateway-selection surface:
 * deterministic selection, persistence, and that smartConnectDecision()'s
 * candidate truthfully reflects whichever gateway is ACTUALLY selected -
 * never a hardcoded Germany default once a different one has been chosen.
 */
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

private fun newViewModel(
    store: SelectedGatewayStore,
    identityStore: net.pocvpn.client.vpn.config.ClientTunnelIdentityStore? = null,
) = MainViewModel(
    clientKeyRepository = FakeClientKeyRepository(),
    transport = FakeVpnTransport(),
    gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
    reconnectManager = FakeReconnectManager(),
    diagnosticsStore = DiagnosticsStore(),
    selectedGatewayStore = store,
    clientTunnelIdentityStore = identityStore,
    initialNetworkProfile = USABLE_WIFI,
)

class MainViewModelGatewaySelectionTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `defaults to Germany when nothing has ever been selected`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
    }

    @Test
    fun `selecting Stockholm updates selectedGateway immediately`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    @Test
    fun `selecting a gateway persists it to the store - survives a fresh ViewModel, simulating app restart`() {
        val store = FakeSelectedGatewayStore()
        val viewModel = newViewModel(store)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        val restarted = newViewModel(store)
        assertEquals(ProductionGatewayId.STOCKHOLM, restarted.selectedGateway.value)
    }

    @Test
    fun `selection is deterministic - selecting the same gateway twice never toggles or flips it`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    @Test
    fun `smartConnectDecision candidate reflects Germany by default`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())

        val decision = viewModel.smartConnectDecision() as SmartConnectDecision.Selected

        assertEquals(ProductionGatewayCatalog.GERMANY.endpointId.value, decision.score.candidate.gateway.id)
    }

    @Test
    fun `smartConnectDecision candidate reflects Stockholm once selected - no stale Germany attribution`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())
        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        val decision = viewModel.smartConnectDecision() as SmartConnectDecision.Selected

        assertEquals(ProductionGatewayCatalog.STOCKHOLM.endpointId.value, decision.score.candidate.gateway.id)
        assertNotEquals(ProductionGatewayCatalog.GERMANY.endpointId.value, decision.score.candidate.gateway.id)
    }

    // --- B13 review fix: gateway readiness (ClientTunnelIdentityStore-backed) ---

    @Test
    fun `no identity store wired - every gateway is treated as provisioned, unchanged pre-fix behavior`() {
        val viewModel = newViewModel(FakeSelectedGatewayStore())

        assertTrue(viewModel.isGatewayProvisioned(ProductionGatewayId.GERMANY))
        assertTrue(viewModel.isGatewayProvisioned(ProductionGatewayId.STOCKHOLM))
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), viewModel.provisionedGatewayIds)
    }

    @Test
    fun `only Germany provisioned - Stockholm reports unprovisioned and is excluded from provisionedGatewayIds`() {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val viewModel = newViewModel(FakeSelectedGatewayStore(), identity)

        assertTrue(viewModel.isGatewayProvisioned(ProductionGatewayId.GERMANY))
        assertFalse(viewModel.isGatewayProvisioned(ProductionGatewayId.STOCKHOLM))
        assertEquals(setOf(ProductionGatewayId.GERMANY), viewModel.provisionedGatewayIds)
    }

    @Test
    fun `both provisioned - both report provisioned and both are selectable`() {
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2")
        )
        val viewModel = newViewModel(FakeSelectedGatewayStore(), identity)

        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), viewModel.provisionedGatewayIds)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    @Test
    fun `neither provisioned - provisionedGatewayIds is empty and selecting either gateway is a no-op`() {
        val identity = FakeClientTunnelIdentityStore()
        val store = FakeSelectedGatewayStore()
        val viewModel = newViewModel(store, identity)

        assertEquals(emptySet<ProductionGatewayId>(), viewModel.provisionedGatewayIds)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        // No identity anywhere - the persisted default (Germany) is left
        // exactly as-is, never guessed at or substituted.
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
        assertEquals(0, store.writeCallCount)
    }

    @Test
    fun `selecting an unprovisioned gateway is a no-op - selectedGateway and the store are both unchanged`() {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val store = FakeSelectedGatewayStore()
        val viewModel = newViewModel(store, identity)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
        assertEquals(0, store.writeCallCount)
    }

    @Test
    fun `stale persisted selection - Stockholm was selected but is no longer provisioned, reconciles to Germany`() {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5"))
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)

        val viewModel = newViewModel(store, identity)

        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
        // The reconciliation is PERSISTED, not just an in-memory display fix.
        assertEquals(ProductionGatewayId.GERMANY, store.read())
        assertEquals(1, store.writeCallCount)
    }

    @Test
    fun `stale persisted selection but nothing at all is provisioned - left exactly as persisted, no invented identity`() {
        val identity = FakeClientTunnelIdentityStore()
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)

        val viewModel = newViewModel(store, identity)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
        assertEquals(0, store.writeCallCount)
    }

    @Test
    fun `persisted selection already provisioned - no reconciliation write happens at all`() {
        val identity = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.STOCKHOLM to "10.77.0.2"))
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)

        val viewModel = newViewModel(store, identity)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
        assertEquals(0, store.writeCallCount)
    }

    // --- B13 consolidated review fix (finding 5): active-session location truth ---

    @Test
    fun `selecting a different gateway is a no-op while CONNECTED - the active session's location stays truthful`() = runTest {
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2")
        )
        val store = FakeSelectedGatewayStore()
        val viewModel = newViewModel(store, identity)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        // Still Germany - a real session is exiting through it right now,
        // so Home must not start claiming Sweden.
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
        assertEquals(0, store.writeCallCount)
    }

    @Test
    fun `selecting a different gateway is a no-op while CONNECTING`() = runTest {
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2")
        )
        val transport = FakeVpnTransport().apply { connectGate = kotlinx.coroutines.CompletableDeferred() }
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            clientTunnelIdentityStore = identity,
            initialNetworkProfile = USABLE_WIFI,
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connecting)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
    }

    @Test
    fun `selecting a different gateway succeeds again once DISCONNECTED - not permanently stuck`() = runTest {
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2")
        )
        val viewModel = newViewModel(FakeSelectedGatewayStore(), identity)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)

        viewModel.disconnect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(TransportState.Disconnected, viewModel.transportState.value)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }
}
