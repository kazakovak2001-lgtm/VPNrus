@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.SelectedGatewayStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Test

/**
 * B13 - proves MainViewModel's real, user-facing gateway-selection surface:
 * deterministic selection, persistence, and that smartConnectDecision()'s
 * candidate truthfully reflects whichever gateway is ACTUALLY selected -
 * never a hardcoded Germany default once a different one has been chosen.
 */
private class InMemorySelectedGatewayStore(initial: ProductionGatewayId = ProductionGatewayId.GERMANY) : SelectedGatewayStore {
    var current: ProductionGatewayId = initial
        private set
    var writeCallCount = 0
        private set

    override fun read(): ProductionGatewayId = current
    override fun write(id: ProductionGatewayId) {
        writeCallCount++
        current = id
    }
}

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

private fun newViewModel(store: SelectedGatewayStore) = MainViewModel(
    clientKeyRepository = FakeClientKeyRepository(),
    transport = FakeVpnTransport(),
    gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
    reconnectManager = FakeReconnectManager(),
    diagnosticsStore = DiagnosticsStore(),
    selectedGatewayStore = store,
    initialNetworkProfile = USABLE_WIFI,
)

class MainViewModelGatewaySelectionTest {

    @Before
    fun setUp() {
        Dispatchers.setMain(StandardTestDispatcher())
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `defaults to Germany when nothing has ever been selected`() {
        val viewModel = newViewModel(InMemorySelectedGatewayStore())
        assertEquals(ProductionGatewayId.GERMANY, viewModel.selectedGateway.value)
    }

    @Test
    fun `selecting Stockholm updates selectedGateway immediately`() {
        val viewModel = newViewModel(InMemorySelectedGatewayStore())

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    @Test
    fun `selecting a gateway persists it to the store - survives a fresh ViewModel, simulating app restart`() {
        val store = InMemorySelectedGatewayStore()
        val viewModel = newViewModel(store)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        val restarted = newViewModel(store)
        assertEquals(ProductionGatewayId.STOCKHOLM, restarted.selectedGateway.value)
    }

    @Test
    fun `selection is deterministic - selecting the same gateway twice never toggles or flips it`() {
        val viewModel = newViewModel(InMemorySelectedGatewayStore())

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)
        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    @Test
    fun `smartConnectDecision candidate reflects Germany by default`() {
        val viewModel = newViewModel(InMemorySelectedGatewayStore())

        val decision = viewModel.smartConnectDecision() as SmartConnectDecision.Selected

        assertEquals(ProductionGatewayCatalog.GERMANY.endpointId.value, decision.score.candidate.gateway.id)
    }

    @Test
    fun `smartConnectDecision candidate reflects Stockholm once selected - no stale Germany attribution`() {
        val viewModel = newViewModel(InMemorySelectedGatewayStore())
        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        val decision = viewModel.smartConnectDecision() as SmartConnectDecision.Selected

        assertEquals(ProductionGatewayCatalog.STOCKHOLM.endpointId.value, decision.score.candidate.gateway.id)
        assertNotEquals(ProductionGatewayCatalog.GERMANY.endpointId.value, decision.score.candidate.gateway.id)
    }
}
