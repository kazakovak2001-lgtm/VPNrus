@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
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
 * H2-GATE Gap B - an automatic reconnect restarts Hysteria2 as a NEW session:
 * it must get exactly one fresh S2 sampler owned by the new generation,
 * Protected never carries over, and a launch or sampler from an older
 * generation can neither replace the current sampler nor update its session.
 */
class VpnControllerHysteria2ReconnectGateTest {

    private val WINDOW_MILLIS = 76_000L

    /** [flowing] true: rx grows on every poll (VERIFIED after ~10 s); false: flat counters (IDLE, never VERIFIED). */
    private class Harness(val controller: VpnController, val hysteria: FakeVpnTransport, val reconnect: FakeReconnectManager) {
        var flowing = true
        var rx = 0L
    }

    private fun TestScope.hysteriaHarness(): Harness {
        val hysteria = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        val reconnect = FakeReconnectManager()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            reconnect, DiagnosticsStore(), backgroundScope,
            hysteria2Transport = hysteria,
        )
        val h = Harness(controller, hysteria, reconnect)
        hysteria.dataPlaneProvider = {
            if (h.flowing) h.rx += 900L
            counters(rx = h.rx, tx = 300L)
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

    private suspend fun TestScope.connectVerified(h: Harness) {
        connect(h)
        advanceTimeBy(11_000)
        runCurrent()
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
    }

    private fun TestScope.automaticReconnect(h: Harness) {
        h.reconnect.triggerUnderlyingNetworkChanged()
        runCurrent()
    }

    @Test
    fun `a successful automatic reconnect starts exactly one fresh sampler and re-earns Protected`() = runTest {
        val h = hysteriaHarness()
        connectVerified(h)
        val launchesBefore = h.controller.observationLaunchesForTest
        val generationBefore = h.controller.reconnectGenerationForTest

        automaticReconnect(h)

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(2, h.hysteria.connectCallCount)
        assertTrue(h.controller.reconnectGenerationForTest > generationBefore)
        assertEquals("exactly one new sampler for the restarted session", launchesBefore + 1, h.controller.observationLaunchesForTest)
        assertNotNull(h.controller.progressObservationJobForTest)
        assertEquals("Protected never carries over", VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)

        advanceTimeBy(11_000)
        runCurrent()
        assertEquals(VpnSessionHealth.DirectProtected, h.controller.sessionHealth.value)
        assertEquals(launchesBefore + 1, h.controller.observationLaunchesForTest)
    }

    @Test
    fun `a reconnected session without traffic stays Verifying - Protected is not carried over`() = runTest {
        val h = hysteriaHarness()
        connectVerified(h)

        h.flowing = false
        automaticReconnect(h)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)

        advanceTimeBy(2 * WINDOW_MILLIS)
        runCurrent()
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }

    @Test
    fun `a launch for a stale generation is a no-op and does not cancel the current sampler`() = runTest {
        val h = hysteriaHarness()
        h.flowing = false
        connect(h)
        val current = h.controller.progressObservationJobForTest
        assertNotNull(current)
        val launches = h.controller.observationLaunchesForTest
        val generation = h.controller.reconnectGenerationForTest

        h.controller.launchObservationForTest(EndpointId("stockholm"), h.hysteria, expectedGeneration = generation - 1)
        runCurrent()

        assertSame(current, h.controller.progressObservationJobForTest)
        assertTrue(current!!.isActive)
        assertEquals(launches, h.controller.observationLaunchesForTest)
    }

    @Test
    fun `an Xray automatic reconnect starts no sampler and keeps its Protected semantics`() = runTest {
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        xray.dataPlaneProvider = { TransportStats.Unsupported }
        val reconnect = FakeReconnectManager()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            reconnect, DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(
                XrayProfile(
                    server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                    flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                    realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
                ),
            ),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY))
        runCurrent()
        val launches = controller.observationLaunchesForTest

        reconnect.triggerUnderlyingNetworkChanged()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(2, xray.connectCallCount)
        assertEquals(launches, controller.observationLaunchesForTest)
        assertEquals(VpnSessionHealth.DirectProtected, controller.sessionHealth.value)
    }

    @Test
    fun `the previous generation's sampler cannot verify the reconnected session`() = runTest {
        val h = hysteriaHarness()
        // Traffic flows for 5 s - left alone, this sampler would reach VERIFIED at ~10 s.
        connect(h)
        advanceTimeBy(5_000)
        runCurrent()
        val oldSampler = h.controller.progressObservationJobForTest
        assertNotNull(oldSampler)

        h.flowing = false
        automaticReconnect(h)
        assertTrue("the reconnect cancels the old sampler", oldSampler!!.isCancelled)

        advanceTimeBy(WINDOW_MILLIS)
        runCurrent()
        assertEquals(VpnSessionHealth.DataPlaneVerifying, h.controller.sessionHealth.value)
    }
}
