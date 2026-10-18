@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
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
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
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

/**
 * H2-GATE Gap A - the Hysteria2 data-plane monitor wired into VpnController:
 * idle S1 probes, TX-without-RX revocation, bounded recovery, cancellation,
 * and ownership against reconnects, flaps and lock contention.
 */
class VpnControllerHysteria2MonitorTest {

    /** Traffic model driven by the test: rx/tx grow on every poll while the flags are set. */
    private class Harness(val controller: VpnController, val hysteria: FakeVpnTransport, val diagnostics: DiagnosticsStore, val reconnect: FakeReconnectManager) {
        var rxFlowing = true
        var txFlowing = false
        var statsMode: TransportStats? = null
        var rx = 0L
        var tx = 0L
    }

    private fun TestScope.harness(): Harness {
        val hysteria = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        val diagnostics = DiagnosticsStore()
        val reconnect = FakeReconnectManager()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            reconnect, diagnostics, backgroundScope,
            hysteria2Transport = hysteria,
        )
        val h = Harness(controller, hysteria, diagnostics, reconnect)
        hysteria.dataPlaneProvider = {
            h.statsMode ?: run {
                if (h.rxFlowing) h.rx += 900L
                if (h.txFlowing) h.tx += 300L
                TransportStats.Counters(bytesReceived = h.rx, bytesSent = h.tx, lastHandshakeEpochMillis = null)
            }
        }
        return h
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

    private suspend fun TestScope.protectedSession(h: Harness) {
        connect(h)
        advanceTimeBy(11_000)
        runCurrent()
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        h.rxFlowing = false // idle from here on unless a test says otherwise
    }

    private fun TestScope.advance(millis: Long) {
        advanceTimeBy(millis)
        runCurrent()
    }

    @Test
    fun `S1 never promotes - an unverified session runs no probe and is never torn down by S1`() = runTest {
        val h = harness()
        h.rxFlowing = false
        h.hysteria.sessionProbe = { false }
        connect(h)
        advance(200_000)
        assertEquals(0, h.hysteria.sessionProbeCalls)
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `healthy idle - one S1 probe per minute keeps Protected`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        advance(120_500)
        assertEquals(2, h.hysteria.sessionProbeCalls)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertEquals(1, h.hysteria.maxSessionProbesInFlight)
    }

    @Test
    fun `tx without rx revokes Protected within the verification window, and S1 success does not restore it`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        h.txFlowing = true
        advance(11_000)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        assertTrue(h.controller.state.value is TransportState.Connected)
        advance(60_000)
        assertTrue(h.hysteria.sessionProbeCalls >= 1)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `idle frozen path - S1 fails twice - session ends through DataPlaneNoTraffic`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { false }
        protectedSession(h)
        advance(61_000)
        val state = h.controller.state.value
        assertTrue("expected teardown, was $state", state is TransportState.Error)
        assertEquals(TransportFailureKind.REMOTE_UNCONFIRMED, (state as TransportState.Error).failureKind)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        assertEquals(2, h.hysteria.sessionProbeCalls)
    }

    @Test
    fun `fresh rx recovers Protected only through new-epoch S2 evidence`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        h.statsMode = TransportStats.Unavailable
        advance(1_000)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        h.statsMode = null
        advance(5_000)
        assertEquals("S1 success and live counters alone do not restore", VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        h.rxFlowing = true
        advance(11_000)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
    }

    @Test
    fun `Unsupported after Protected revokes without teardown`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        h.statsMode = TransportStats.Unsupported
        advance(5_000)
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
        h.statsMode = null
        h.rxFlowing = true
        advance(30_000)
        assertEquals("UNVERIFIABLE is final for the session", VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `a probe in flight is cancelled by a user disconnect and changes nothing`() = runTest {
        val h = harness()
        val gate = CompletableDeferred<Boolean>()
        var cancelled = false
        h.hysteria.sessionProbe = {
            try { gate.await() } catch (e: kotlinx.coroutines.CancellationException) { cancelled = true; throw e }
        }
        protectedSession(h)
        advance(60_500)
        assertEquals(1, h.hysteria.sessionProbesInFlight)
        h.controller.disconnect()
        runCurrent()
        assertTrue(cancelled)
        assertEquals(0, h.hysteria.sessionProbesInFlight)
        gate.complete(false)
        advance(60_000)
        assertTrue(h.controller.state.value is TransportState.Disconnected)
    }

    @Test
    fun `a probe in flight is cancelled by an automatic reconnect and cannot touch the new session`() = runTest {
        val h = harness()
        val gate = CompletableDeferred<Boolean>()
        h.hysteria.sessionProbe = { gate.await() }
        protectedSession(h)
        advance(60_500)
        assertEquals(1, h.hysteria.sessionProbesInFlight)
        h.rxFlowing = true
        h.reconnect.triggerUnderlyingNetworkChanged()
        runCurrent()
        assertEquals(0, h.hysteria.sessionProbesInFlight)
        gate.complete(false) // a late "failure" for the old session
        advance(11_000)
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertNotEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `a transport flap within the same generation does not inherit Protected (connectedEpoch)`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        h.rxFlowing = true
        h.hysteria.forceState(TransportState.Error("Hysteria2 runtime failed"))
        runCurrent()
        h.hysteria.forceState(TransportState.Connected)
        runCurrent()
        advance(30_000)
        assertNotEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
    }

    @Test
    fun `a same-generation Disconnected-Connected flap never yields Protected for the later period`() = runTest {
        val h = harness()
        h.rxFlowing = false
        connect(h)
        // Disconnected -> Connected from the transport itself (no reconnect, same
        // generation). The old monitor is already gone here; connectedEpoch in the
        // ownership predicate is defense in depth for this case, not the only guard.
        h.hysteria.forceState(TransportState.Disconnected)
        runCurrent()
        h.hysteria.forceState(TransportState.Connected)
        runCurrent()
        h.rxFlowing = true
        advance(30_000)
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `an old monitor blocked on connectMutex cannot mutate the session after a reconnect`() = runTest {
        val h = harness()
        h.hysteria.sessionProbe = { true }
        protectedSession(h)
        val release = CompletableDeferred<Unit>()
        backgroundScope.launch { h.controller.holdConnectMutexForTest(release) }
        runCurrent()
        h.statsMode = TransportStats.Unavailable // the old monitor now wants to revoke, but waits for connectMutex
        advance(1_000)
        h.reconnect.triggerUnderlyingNetworkChanged() // bumps the generation and cancels the old monitor
        runCurrent()
        h.statsMode = null
        h.rxFlowing = true
        release.complete(Unit)
        advance(11_000)
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertEquals("only the reconnect's own restart disconnected the transport", 1, h.hysteria.disconnectCallCount)
    }
}
