@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.smartconnect.TrafficProgressOutcome
import net.pocvpn.client.smartconnect.TransportAttemptProtocol
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.xray.XrayProcessBridge
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val XRAY_PROFILE = XrayProfile(
    server = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
)

private fun gateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val network = NetworkProfile(
    type = NetworkType.WIFI,
    validatedInternet = true,
    metered = false,
    roaming = false,
    captivePortal = false,
    ipv4Available = true,
    ipv6Available = false,
    vpnActive = false,
    generation = 1,
    dnsServerAddresses = listOf("1.1.1.1"),
)

/**
 * B-WL7 extended to Direct Xray: after the B33-confirmed Connected, the same
 * bounded progress check runs on the transport's dataPlaneCounters() (the
 * `:xray` VLESS byte totals in production) and ends a session whose tunnel
 * carries nothing back with DataPlaneNoTraffic.
 */
class VpnControllerXrayDataPlaneGateTest {

    private class Harness(val controller: VpnController, val xray: FakeVpnTransport, val diagnostics: DiagnosticsStore, val store: TransportObservationStore)

    private fun TestScope.connectXray(dataPlane: (Int) -> TransportStats): Harness {
        val diagnostics = DiagnosticsStore()
        val store = TransportObservationStore()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(XRAY_PROFILE),
            transportObservationStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { network },
        )
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        var polls = 0
        xray.dataPlaneProvider = { polls++; dataPlane(polls) }
        return Harness(controller, xray, diagnostics, store)
    }

    private suspend fun TestScope.start(h: Harness) {
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()
    }

    private fun fingerprint() = NetworkFingerprinter.fingerprint(
        CoarseNetworkSignals(network.type, network.dnsServerAddresses),
        byteArrayOf(1, 2, 3, 4),
    )

    @Test
    fun `Xray uplink with no downlink ends the session with DataPlaneNoTraffic`() = runTest {
        val h = connectXray { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        start(h)
        assertTrue(h.controller.state.value is TransportState.Connected)

        advanceTimeBy(31_000)
        runCurrent()

        val state = h.controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals(TransportFailureKind.REMOTE_UNCONFIRMED, (state as TransportState.Error).failureKind)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        assertTrue(h.xray.disconnectCallCount >= 1)
        val observation = h.store.recent(fingerprint()).single()
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, observation.progress)
        assertEquals(TransportAttemptProtocol.TCP, observation.protocol)
    }

    @Test
    fun `B33 confirmation bytes then a stall also end the session`() = runTest {
        val h = connectXray { n -> TransportStats.Counters(bytesReceived = 512L, bytesSent = 1_000L + n * 300L, lastHandshakeEpochMillis = null) }
        start(h)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Error)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `a working or idle Xray session stays Connected`() = runTest {
        val working = connectXray { n -> TransportStats.Counters(bytesReceived = n * 900L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        val idle = connectXray { _ -> TransportStats.Counters(bytesReceived = 512L, bytesSent = 300L, lastHandshakeEpochMillis = null) }
        start(working)
        start(idle)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(working.controller.state.value is TransportState.Connected)
        assertTrue(idle.controller.state.value is TransportState.Connected)
        assertEquals(0, working.xray.disconnectCallCount)
        assertEquals(TrafficProgressOutcome.SUSTAINED, working.store.recent(fingerprint()).single().progress)
    }

    @Test
    fun `a transport without byte counts is untouched and adds no observation`() = runTest {
        val h = connectXray { _ -> TransportStats.Unsupported }
        start(h)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `an unreachable xray process gives no samples - no teardown, no observation`() = runTest {
        val h = connectXray { _ -> TransportStats.Unavailable }
        start(h)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `a user disconnect during the window wins`() = runTest {
        val h = connectXray { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        start(h)
        advanceTimeBy(5_000)
        runCurrent()

        h.controller.disconnect()
        runCurrent()
        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Disconnected)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `an Xray Failed mid-window ends as that Error - the gate never adds its own teardown`() = runTest {
        // Uplink with no downlink: left alone, the gate would end this as DataPlaneNoTraffic.
        val h = connectXray { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        start(h)
        advanceTimeBy(5_000)
        runCurrent()

        // What VlessRealityTransport maps a death-time Failed of its session to.
        val error = requireNotNull(xrayTransportStateFor(XrayRuntimeEvent.Failed(77L, XrayProcessBridge.DIED_REASON), sessionId = 77L))
        h.xray.forceState(error)
        runCurrent()
        advanceTimeBy(31_000)
        runCurrent()

        val state = h.controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals(XrayProcessBridge.DIED_REASON, (state as TransportState.Error).message)
        assertEquals(VpnError.HandshakeTimeout, h.diagnostics.snapshot.value.lastError)
        assertEquals(0, h.xray.disconnectCallCount)
    }
}
