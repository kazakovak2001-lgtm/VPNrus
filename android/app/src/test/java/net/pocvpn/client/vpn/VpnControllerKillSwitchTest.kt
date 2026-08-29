@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8G/B8G1 - narrow tests for the app-session kill-switch invariant: an
 * automatic failure/reconnect cycle must never itself call
 * transport.connect() OR transport.disconnect() (see VpnController
 * .reconnectLoop's own "Break-before-make" docs for why re-calling connect()
 * would itself reopen the leak window this whole slice exists to close) -
 * only an explicit user connect()/disconnect() may touch the transport.
 * Reuses FakeVpnControllerDeps' existing fakes; no new test infrastructure.
 *
 * Deliberately uses bounded advanceTimeBy(...) with a generous margin
 * everywhere, never advanceUntilIdle() - empirically, advanceUntilIdle()
 * does not reliably drain this suite's multi-attempt reconnect loop (a
 * real, isolated repro showed it settling back on a stale pre-reconnect
 * Connected value with reconnectAttempts left at 0, i.e. as if the loop
 * never ran at all, even though a single large bounded advanceTimeBy over
 * the identical scenario resolves correctly and consistently). Not
 * investigated further here since it is a kotlinx-coroutines-test question,
 * not a VpnController correctness question - bounded advances are also
 * exactly the pattern this repo's own pre-existing reconnect tests already use.
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

class VpnControllerKillSwitchTest {

    @Test
    fun `initial connect calls transport connect exactly once`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(1, transport.connectCallCount)
    }

    @Test
    fun `network loss after Protected enters Reconnecting without calling transport connect or disconnect again`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        reconnectManager.triggerNetworkLost()
        runCurrent()

        assertTrue("expected Reconnecting, was ${controller.state.value}", controller.state.value is TransportState.Reconnecting)
        // B8G1: the SAME established tunnel/VpnService interface stays
        // owned by this one original transport.connect() call - reconnect
        // never re-establishes it (see VpnController.reconnectLoop's docs).
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `a failed handshake never becomes Protected, and the session stays up without any further connect calls`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        // The tunnel starts failing to handshake - the reconnect loop keeps
        // polling, but the session must stay "held" (never Connected, never
        // torn down, never re-established) for as long as it keeps failing.
        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        // The network itself is fine throughout - only the AWG tunnel/
        // handshake keeps failing.
        reconnectManager.networkAvailable = true
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        // Comfortably covers several failed recovery-poll cycles without
        // yet exhausting MAX_ATTEMPTS.
        advanceTimeBy(45_000)
        runCurrent()
        assertFalse("must not be Connected without a fresh handshake", controller.state.value is TransportState.Connected)
        // B8G1: recovery never calls transport.connect() again - it only
        // polls the SAME session's stats() for a fresh handshake.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `recovery reaches Protected once a FRESH handshake is observed, without ever calling transport connect or disconnect again`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        reconnectManager.networkAvailable = true
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        advanceTimeBy(45_000)
        runCurrent()
        assertFalse("must not be Connected without a fresh handshake", controller.state.value is TransportState.Connected)

        // Now the tunnel actually recovers on its own (exactly like real
        // AmneziaWG/WireGuard's own protocol-level handshake retry, backed
        // by PersistentKeepalive - see VpnController's own docs) - the very
        // next recovery poll observes a fresh handshake and ONLY THEN may
        // the state read Protected. A generous bounded advance (never
        // advanceUntilIdle - see this test class's own note) lets that next
        // poll cycle run to completion.
        transport.handshakeAvailable = true
        advanceTimeBy(300_000)
        runCurrent()

        assertTrue("expected Connected after a real fresh handshake, was ${controller.state.value}", controller.state.value is TransportState.Connected)
        // The whole recovery - failing AND succeeding - never touched
        // transport.connect()/disconnect() again. The SAME session, the
        // SAME VpnService interface, the SAME routes throughout.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `exhausted reconnect attempts settle on Error, never silently restore direct network access, and never re-call connect`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        reconnectManager.networkAvailable = true
        // A single large bounded advance (never advanceUntilIdle - see this
        // test class's own note) comfortably covers all 8 attempts' worst-
        // case backoff-plus-handshake-timeout total (a little over 200s).
        advanceTimeBy(300_000)
        runCurrent()

        assertTrue("expected Error(exhausted), was ${controller.state.value}", controller.state.value is TransportState.Error)
        assertEquals(VpnError.ReconnectExhausted, diagnostics.snapshot.value.lastError)
        // B8G1: exhaustion is reached purely by polling - the original
        // tunnel is never re-established or torn down along the way.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `state never resolves to Disconnected on its own during an automatic reconnect cycle`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
        )
        val observedStates = mutableListOf<TransportState>()
        val collectJob = backgroundScope.launch { controller.state.collect { observedStates.add(it) } }

        controller.connect()
        runCurrent()
        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        reconnectManager.networkAvailable = true
        // A single large bounded advance (never advanceUntilIdle - see this
        // test class's own note) comfortably covers exhaustion of all 8 attempts.
        advanceTimeBy(300_000)
        runCurrent()

        // Disconnected is the ONLY state that means "no VPN session, ISP
        // network directly reachable" - an automatic cycle (however it ends)
        // must never produce it on its own; only explicit disconnect() may.
        assertTrue(
            "Disconnected must never appear automatically: $observedStates",
            observedStates.none { it is TransportState.Disconnected },
        )
        collectJob.cancel()
    }

    @Test
    fun `explicit user DISCONNECT is the only path that tears down the session and restores normal networking`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)
        assertEquals(0, transport.disconnectCallCount)

        controller.disconnect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.disconnectCallCount)

        // User-initiated disconnect must permanently suppress auto-reconnect,
        // even across many backoff intervals.
        advanceTimeBy(300_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.disconnectCallCount)
    }

    @Test
    fun `network-change-triggered recovery uses the SAME polling path - no bypass branch, no re-established tunnel`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertEquals(1, transport.connectCallCount)

        // Simulates a Wi-Fi -> mobile transition: the underlying network is
        // momentarily lost, then a (different) network becomes available.
        reconnectManager.triggerNetworkLost()
        runCurrent()
        val maxJitter = { 1.0 }
        reconnectManager.triggerNetworkAvailable()
        advanceTimeBy(ReconnectBackoff.delayForAttempt(1, maxJitter) + 50)
        runCurrent()

        // Recovery happened purely by polling the SAME still-established
        // session for a fresh handshake - never a second transport.connect()
        // call, never a distinct "resume direct networking" branch.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }
}
