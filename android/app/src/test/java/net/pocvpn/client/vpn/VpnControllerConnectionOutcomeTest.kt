@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I - narrow tests proving VpnController records ConnectionOutcome ONLY
 * from real evidence: this feature's own required cases 6, 7, 8, plus 12/13
 * re-affirmed alongside the new wiring (no regression to B8G1's own
 * "reconnect never calls transport.connect()/disconnect()" invariant now
 * that outcome recording exists).
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

class VpnControllerConnectionOutcomeTest {

    @Test
    fun `a real fresh handshake records exactly one SUCCESS outcome with a measured duration`() = runTest {
        val transport = FakeVpnTransport()
        val outcomeStore = FakeConnectionOutcomeStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            connectionOutcomeStore = outcomeStore,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(1, outcomeStore.recent().size)
        val outcome = outcomeStore.recent().single()
        assertEquals(ConnectionOutcomeResult.SUCCESS, outcome.result)
        assertEquals(ConnectionErrorCategory.NONE, outcome.errorCategory)
        assertEquals(TransportKind.AMNEZIA_WG, outcome.transport)
        assertEquals(ProductionGateway.ID, outcome.gatewayId)
        assertNotNull(outcome.handshakeDurationMs)
        assertTrue(outcome.handshakeDurationMs!! >= 0)
    }

    @Test
    fun `a handshake timeout records exactly one FAILURE outcome with HANDSHAKE_TIMEOUT and a measured duration`() = runTest {
        val transport = FakeVpnTransport()
        transport.handshakeAvailable = false
        val outcomeStore = FakeConnectionOutcomeStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            connectionOutcomeStore = outcomeStore,
        )

        controller.connect()
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.HandshakeFailed)
        assertEquals(1, outcomeStore.recent().size)
        val outcome = outcomeStore.recent().single()
        assertEquals(ConnectionOutcomeResult.FAILURE, outcome.result)
        assertEquals(ConnectionErrorCategory.HANDSHAKE_TIMEOUT, outcome.errorCategory)
        assertNotNull(outcome.handshakeDurationMs)
    }

    @Test
    fun `no connectionOutcomeStore wired records nothing - purely additive, no crash`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `exhausted reconnect records exactly one FAILURE outcome for the whole cycle, not one per attempt`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val outcomeStore = FakeConnectionOutcomeStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            connectionOutcomeStore = outcomeStore,
        )

        controller.connect()
        runCurrent()
        assertEquals(1, outcomeStore.recent().size) // the initial successful connect

        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        reconnectManager.networkAvailable = true
        advanceTimeBy(300_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        // Exactly ONE new outcome for the entire exhausted cycle (the
        // initial SUCCESS above, plus this one RECONNECT_EXHAUSTED failure).
        assertEquals(2, outcomeStore.recent().size)
        val exhaustionOutcome = outcomeStore.recent().last()
        assertEquals(ConnectionOutcomeResult.FAILURE, exhaustionOutcome.result)
        assertEquals(ConnectionErrorCategory.RECONNECT_EXHAUSTED, exhaustionOutcome.errorCategory)

        // B8G1 unchanged: the reconnect cycle - now recording outcomes too -
        // still never re-calls transport.connect()/disconnect().
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `network loss that recovers without exhausting never calls transport connect or disconnect, outcome recording included`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val outcomeStore = FakeConnectionOutcomeStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            connectionOutcomeStore = outcomeStore,
        )

        controller.connect()
        runCurrent()
        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        // Recovers immediately (handshakeAvailable stays true throughout).
        reconnectManager.networkAvailable = true
        advanceTimeBy(5_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
        // Only the initial connect's SUCCESS - a recovered-without-exhausting
        // cycle is not itself a new recorded outcome (see reconnectLoop's docs).
        assertEquals(1, outcomeStore.recent().size)
    }
}
