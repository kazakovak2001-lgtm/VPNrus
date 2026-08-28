@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8B3D - narrow tests for the new boundary only: truthful, handshake-aware
 * CONNECTED state. Reuses FakeVpnControllerDeps.FakeVpnTransport's new
 * stats() support (handshakeAvailable/statsBytesSent) - no new test
 * infrastructure.
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0"),
    profile = AwgProfile.none(),
)

class VpnControllerHandshakeTest {

    @Test
    fun `CONNECT immediately shows CONNECTING, before any handshake is known`() = runTest {
        val transport = FakeVpnTransport()
        transport.connectGate = CompletableDeferred() // holds connect() open mid-flight
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        val job = backgroundScope.launch { controller.connect() }
        runCurrent()

        assertTrue("expected Connecting, was ${controller.state.value}", controller.state.value is TransportState.Connecting)

        transport.connectGate!!.complete(Unit)
        job.cancel()
    }

    @Test
    fun `a fresh handshake within the startup window produces CONNECTED`() = runTest {
        val transport = FakeVpnTransport() // handshakeAvailable=true by default
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue("expected Connected, was ${controller.state.value}", controller.state.value is TransportState.Connected)
    }

    @Test
    fun `no handshake within the startup window produces HANDSHAKE_FAILED, not CONNECTED`() = runTest {
        val transport = FakeVpnTransport()
        transport.handshakeAvailable = false
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        advanceTimeBy(15_000) // comfortably past the bounded startup window
        runCurrent()

        assertTrue("expected HandshakeFailed, was ${controller.state.value}", controller.state.value is TransportState.HandshakeFailed)
        assertEquals(VpnError.HandshakeTimeout, diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `TX greater than zero without a handshake still does NOT mean CONNECTED`() = runTest {
        val transport = FakeVpnTransport()
        transport.handshakeAvailable = false
        transport.statsBytesSent = 4096 // interface up, junk/keepalive traffic flowing, no real handshake
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        advanceTimeBy(15_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.HandshakeFailed)
    }

    @Test
    fun `an established CONNECTED session is not re-evaluated later as handshake age grows`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        // Simulate a long idle period - no code path re-polls stats() for an
        // already-connected session (awaitFreshHandshake runs exactly once,
        // inside doConnectAttempt, never again while state stays Connected).
        advanceTimeBy(60 * 60_000) // 1 hour
        runCurrent()

        assertTrue(
            "an idle CONNECTED session must never flip to HandshakeFailed on its own: was ${controller.state.value}",
            controller.state.value is TransportState.Connected,
        )
    }

    @Test
    fun `DISCONNECT resets attempt state - a subsequent failed attempt is judged fresh, not by the old session`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        controller.disconnect()
        runCurrent()
        assertTrue("expected Disconnected, was ${controller.state.value}", controller.state.value is TransportState.Disconnected)

        // A second, independent attempt - now failing - must be judged on
        // its own merits, not short-circuited by the earlier success.
        transport.handshakeAvailable = false
        controller.connect()
        advanceTimeBy(15_000)
        runCurrent()

        assertTrue("expected HandshakeFailed, was ${controller.state.value}", controller.state.value is TransportState.HandshakeFailed)
    }
}
