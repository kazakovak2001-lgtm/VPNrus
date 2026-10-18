@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Hysteria2Profile
import net.pocvpn.client.reachability.withHysteria2Profile
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private fun gateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private fun counters(rx: Long, tx: Long) = TransportStats.Counters(bytesReceived = rx, bytesSent = tx, lastHandshakeEpochMillis = null)

/**
 * H2-GATE - Hysteria2 is Protected only after a fresh, session-scoped B-WL7
 * VERIFIED from the tun2socks child's own TUN<->SOCKS counters (S2).
 * Connected, the connect-time probe, idle, unsupported/stale counters and
 * stale results never mean Protected; a dead data plane ends the session
 * through the existing DataPlaneNoTraffic path (no direct fallback).
 */
class VpnControllerHysteria2DataPlaneGateTest {

    // Hysteria2 uses the payload-only 65s stall window: one bounded window is 10s + 65s.
    private val WINDOW_MILLIS = 76_000L

    private class Harness(val controller: VpnController, val hysteria: FakeVpnTransport, val diagnostics: DiagnosticsStore)

    private fun TestScope.harness(dataPlane: (Int) -> TransportStats): Harness {
        val diagnostics = DiagnosticsStore()
        val hysteria = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        var polls = 0
        hysteria.dataPlaneProvider = { polls++; dataPlane(polls) }
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            hysteria2Transport = hysteria,
        )
        return Harness(controller, hysteria, diagnostics)
    }

    private suspend fun TestScope.connect(h: Harness) {
        h.controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                h.hysteria, TransportKind.HYSTERIA2,
                endpointId = EndpointId("stockholm"),
                endpointTransportBinding = EndpointTransportBinding(kind = TransportKind.HYSTERIA2, host = "16.170.208.231", port = 443)
                    .withHysteria2Profile(Hysteria2Profile(sni = "origin-sthlm.aknova.pp.ua", obfuscationMode = "NONE")),
            ),
        )
        runCurrent()
    }

    @Test
    fun `Connected alone is DataPlaneVerifying, never Protected`() = runTest {
        val h = harness { _ -> TransportStats.Unavailable }
        connect(h)

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `real two-way traffic through the TUN leg lifts the session to Protected`() = runTest {
        val h = harness { n -> counters(rx = n * 900L, tx = n * 300L) }
        connect(h)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)

        advanceTimeBy(11_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertEquals(0, h.hysteria.disconnectCallCount)
    }

    @Test
    fun `an idle session is neither Protected nor failed, and keeps sampling until traffic proves it`() = runTest {
        var trafficStarted = false
        var rx = 512L
        val h = harness { _ ->
            if (trafficStarted) rx += 900L
            counters(rx = rx, tx = 300L)
        }
        connect(h)

        // Three full windows of flat counters: IDLE each time, never a teardown, never Protected.
        advanceTimeBy(3 * WINDOW_MILLIS)
        runCurrent()
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        assertEquals(0, h.hysteria.disconnectCallCount)
        assertTrue(h.diagnostics.snapshot.value.lastError != VpnError.DataPlaneNoTraffic)

        trafficStarted = true
        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
    }

    @Test
    fun `unsupported counters (missing or pre-H2-GATE child) never reach Protected and are not torn down`() = runTest {
        val h = harness { _ -> TransportStats.Unsupported }
        connect(h)

        advanceTimeBy(3 * WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        assertEquals(0, h.hysteria.disconnectCallCount)
    }

    @Test
    fun `stale stats (no fresh sample) never count as progress`() = runTest {
        val h = harness { _ -> TransportStats.Unavailable }
        connect(h)

        advanceTimeBy(2 * WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `stats that stop mid-check stop the progress - an earlier rise alone is not enough`() = runTest {
        // One rx rise, then the stream goes stale: VERIFIED needs two rises over 10s.
        val h = harness { n -> if (n <= 2) counters(rx = n * 900L, tx = n * 300L) else TransportStats.Unavailable }
        connect(h)

        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()

        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `uplink with no downlink past the 65s stall window ends the session with DataPlaneNoTraffic`() = runTest {
        val h = harness { n -> counters(rx = 0L, tx = n * 300L) }
        connect(h)

        advanceTimeBy(60_000)
        runCurrent()
        assertTrue("not before the payload-only stall window", h.controller.state.value is TransportState.Connected)

        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()
        val state = h.controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals(TransportFailureKind.REMOTE_UNCONFIRMED, (state as TransportState.Error).failureKind)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        assertTrue(h.hysteria.disconnectCallCount >= 1)
        assertTrue(h.controller.sessionHealth.value is VpnSessionHealth.Failed)
    }

    @Test
    fun `a verified session loses Protected the moment it leaves Connected, and a new session must earn it again`() = runTest {
        var rx = 0L
        var flowing = true
        val h = harness { _ ->
            if (flowing) rx += 900L
            counters(rx = rx, tx = 300L)
        }
        connect(h)
        advanceTimeBy(11_000)
        runCurrent()
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)

        h.controller.disconnect()
        runCurrent()
        assertEquals(VpnSessionHealth.Idle, h.controller.sessionHealth.value)

        flowing = false
        connect(h)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `an old idle session's window never touches the next session's own check`() = runTest {
        var rx = 512L
        var flowing = false
        val h = harness { _ ->
            if (flowing) rx += 900L
            counters(rx = rx, tx = 300L)
        }
        connect(h)
        advanceTimeBy(40_000)
        runCurrent()

        h.controller.disconnect()
        runCurrent()
        flowing = true
        connect(h)
        // Past the first session's original window end and its would-be continuation.
        advanceTimeBy(2 * WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertEquals(1, h.hysteria.disconnectCallCount)
    }

    @Test
    fun `a check that finishes after the user disconnected cannot mark anything Protected`() = runTest {
        val h = harness { n -> counters(rx = n * 900L, tx = n * 300L) }
        connect(h)
        advanceTimeBy(3_000)
        runCurrent()

        h.controller.disconnect()
        runCurrent()
        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Disconnected)
        assertEquals(VpnSessionHealth.Idle, h.controller.sessionHealth.value)
    }

    @Test
    fun `transport Error mid-check ends as that Error - no Protected, no gate teardown`() = runTest {
        val h = harness { n -> counters(rx = n * 900L, tx = n * 300L) }
        connect(h)
        advanceTimeBy(3_000)
        runCurrent()

        h.hysteria.forceState(TransportState.Error("Hysteria2 runtime failed"))
        runCurrent()
        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.sessionHealth.value is VpnSessionHealth.Failed)
        assertTrue(h.diagnostics.snapshot.value.lastError != VpnError.DataPlaneNoTraffic)
    }

    @Test
    fun `other transports keep Connected as Protected - Xray is not gated`() = runTest {
        val diagnostics = DiagnosticsStore()
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        xray.dataPlaneProvider = { TransportStats.Unsupported }
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(
                net.pocvpn.client.identity.XrayProfile(
                    server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                    flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                    realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
                ),
            ),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY))
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, controller.sessionHealth.value)
    }
}
