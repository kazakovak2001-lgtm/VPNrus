@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val BUDGET_TEST_TLS_PROFILE = XrayTlsProfile(
    server = "152.70.43.1",
    serverPort = 2053,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    serverName = "203.0.113.1",
    fingerprint = "chrome",
)

/**
 * Smart Connect re-evaluation after a network change: the same-path restart
 * budget after a Wi-Fi <-> mobile change is configurable (Auto shortens it,
 * then reselects); a plain network loss always keeps the full budget.
 */
class VpnControllerNetworkChangeBudgetTest {

    private class Harness(val controller: VpnController, val transport: FakeVpnTransport, val reconnect: FakeReconnectManager, val diagnostics: DiagnosticsStore, val events: MutableList<ReconnectIncidentEvent>)

    private fun TestScope.harness(attempts: () -> Int = { ReconnectBackoff.MAX_ATTEMPTS }): Harness {
        val transport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val reconnect = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val events = mutableListOf<ReconnectIncidentEvent>()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(
                GatewayConfiguration.Configured(
                    endpointHost = "203.0.113.10",
                    endpointPort = 51820,
                    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
                    clientTunnelIp = "10.77.0.2",
                    gatewayTunnelIp = "10.77.0.1",
                    allowedIps = listOf("0.0.0.0/0"),
                    profile = AwgProfile.none(),
                ),
            ),
            reconnect, diagnostics, backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(BUDGET_TEST_TLS_PROFILE),
            onReconnectIncident = events::add,
            networkChangeReconnectAttempts = attempts,
        )
        return Harness(controller, transport, reconnect, diagnostics, events)
    }

    private suspend fun TestScope.connectThenBreakRestarts(h: Harness) {
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.transport, TransportKind.TLS_TCP))
        runCurrent()
        assertTrue(h.controller.state.value is TransportState.Connected)
        // A real transport reports a terminal Error when the path is dead.
        h.transport.reportErrorAfterConnect = "path dead on the new network"
    }

    private fun TestScope.finish() {
        advanceTimeBy(400_000)
        runCurrent()
    }

    private fun Harness.assertExhausted(restarts: Int) {
        assertEquals("1 initial connect + $restarts restarts", 1 + restarts, transport.connectCallCount)
        assertTrue("state ${controller.state.value}", controller.state.value is TransportState.Error)
        // The exhaustion is signalled by the event flag; diagnostics' lastError
        // can be overwritten afterwards by the async transport-state observer.
        val failed = events.filterIsInstance<ReconnectIncidentEvent.Failed>().single()
        assertTrue(failed.recoveryExhausted)
    }

    @Test
    fun `default network-change budget is unchanged`() = runTest {
        val h = harness()
        connectThenBreakRestarts(h)
        h.reconnect.triggerUnderlyingNetworkChanged()
        finish()
        h.assertExhausted(ReconnectBackoff.MAX_ATTEMPTS)
    }

    @Test
    fun `a shortened budget gives up after that many restarts`() = runTest {
        val h = harness { 3 }
        connectThenBreakRestarts(h)
        h.reconnect.triggerUnderlyingNetworkChanged()
        runCurrent()
        advanceTimeBy(10_000) // 1 immediate + ~2 s + ~4 s (+ jitter) - well under the full budget
        runCurrent()
        h.assertExhausted(3)
    }

    @Test
    fun `a plain network loss keeps the full budget even when the network-change budget is short`() = runTest {
        val h = harness { 3 }
        connectThenBreakRestarts(h)
        h.reconnect.triggerNetworkLost()
        h.reconnect.triggerNetworkAvailable()
        finish()
        h.assertExhausted(ReconnectBackoff.MAX_ATTEMPTS)
    }

    @Test
    fun `out-of-range and throwing budgets are clamped`() = runTest {
        val zero = harness { 0 }
        connectThenBreakRestarts(zero)
        zero.reconnect.triggerUnderlyingNetworkChanged()
        finish()
        zero.assertExhausted(1)

        val throwing = harness { error("store unavailable") }
        connectThenBreakRestarts(throwing)
        throwing.reconnect.triggerUnderlyingNetworkChanged()
        finish()
        throwing.assertExhausted(ReconnectBackoff.MAX_ATTEMPTS)
    }
}
