@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.MapXrayXhttpProfileRepositoryResolver
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.identity.XrayXhttpProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.smartconnect.ProductionGateway
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

private val XRAY_TLS_PROFILE = XrayTlsProfile(
    server = "152.70.43.1",
    serverPort = 2053,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    serverName = "203.0.113.1",
    fingerprint = "chrome",
)

private val XRAY_XHTTP_PROFILE = XrayXhttpProfile(
    server = "edge.aknova.pp.ua",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    xhttpHost = "edge.aknova.pp.ua",
    xhttpPath = "/nova-xhttp/",
    mode = "packet-up",
    uplinkHttpMethod = "POST",
    fingerprint = "chrome",
)

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

    // P2: the bounded Xray check now spans verification (10s) + stall (65s), so "past the window" is > 75s.
    private val XRAY_WINDOW_MILLIS = 76_000L

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

        advanceTimeBy(XRAY_WINDOW_MILLIS)
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

        advanceTimeBy(XRAY_WINDOW_MILLIS)
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

        advanceTimeBy(XRAY_WINDOW_MILLIS)
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

        advanceTimeBy(XRAY_WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `an unreachable xray process gives no samples - no teardown, no observation`() = runTest {
        val h = connectXray { _ -> TransportStats.Unavailable }
        start(h)

        advanceTimeBy(XRAY_WINDOW_MILLIS)
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
        advanceTimeBy(XRAY_WINDOW_MILLIS)
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
        advanceTimeBy(XRAY_WINDOW_MILLIS)
        runCurrent()

        val state = h.controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals(XrayProcessBridge.DIED_REASON, (state as TransportState.Error).message)
        assertEquals(VpnError.HandshakeTimeout, h.diagnostics.snapshot.value.lastError)
        assertEquals(0, h.xray.disconnectCallCount)
    }

    @Test
    fun `P2 - Xray uplink-only is not torn down at 20s, only after the 65s stall window`() = runTest {
        // This harness wires only a REALITY profile; TLS_TCP/XRAY_XHTTP get the same policy from
        // TrafficProgressPolicy.forTransport(transport.kind) - covered in TrafficProgressMonitorTest.
        val h = connectXray { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        start(h)

        advanceTimeBy(21_000)
        runCurrent()
        assertTrue("at 21s", h.controller.state.value is TransportState.Connected)

        advanceTimeBy(43_000) // 64s
        runCurrent()
        assertTrue("at 64s", h.controller.state.value is TransportState.Connected)
        assertEquals(0, h.xray.disconnectCallCount)

        advanceTimeBy(2_000) // 66s
        runCurrent()
        assertTrue("at 66s", h.controller.state.value is TransportState.Error)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, h.store.recent(fingerprint()).single().progress)
    }

    // P2 diagnostics - the same 65s gate for every Direct Xray kind, and the logged line names the applied policy.

    private fun TestScope.connectXrayKind(kind: TransportKind, dataPlane: (Int) -> TransportStats): Harness {
        val diagnostics = DiagnosticsStore()
        val store = TransportObservationStore()
        val endpoint = EndpointId(ProductionGateway.ID)
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(XRAY_PROFILE),
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(XRAY_TLS_PROFILE),
            xrayXhttpProfileRepositoryResolver = MapXrayXhttpProfileRepositoryResolver(mapOf(endpoint to FakeXrayXhttpProfileRepository(XRAY_XHTTP_PROFILE))),
            transportObservationStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { network },
        )
        val xray = FakeVpnTransport(kind = kind, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        var polls = 0
        xray.dataPlaneProvider = { polls++; dataPlane(polls) }
        return Harness(controller, xray, diagnostics, store)
    }

    @Test
    fun `P2 - every Direct Xray kind keeps a TX-only session at 64s and ends it after 65s, logging the 65s policy`() {
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP, TransportKind.XRAY_XHTTP)) {
            runTest {
                val h = connectXrayKind(kind) { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
                h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, kind))
                runCurrent()
                assertTrue("$kind connected", h.controller.state.value is TransportState.Connected)

                advanceTimeBy(64_000)
                runCurrent()
                assertTrue("$kind at 64s", h.controller.state.value is TransportState.Connected)
                assertEquals(kind.name, null, h.controller.lastDataPlaneCheckDiagnostic)

                advanceTimeBy(2_000) // 66s
                runCurrent()
                assertTrue("$kind at 66s", h.controller.state.value is TransportState.Error)
                assertEquals(kind.name, VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
                val line = h.controller.lastDataPlaneCheckDiagnostic!!
                assertTrue(line, line.startsWith("B-WL7 data-plane check: kind=$kind verdict=NO_PAYLOAD samples=131 rx=0 tx="))
                assertTrue(line, line.endsWith(" stallWindowMs=65000 verificationWindowMs=10000 silentForMs=65000 polls=131 maxPolls=150 end=DECISIVE_VERDICT"))
            }
        }
    }

    @Test
    fun `a check that never turns decisive runs all 151 polls and logs WINDOW_EXHAUSTED without teardown`() = runTest {
        // One RX advance only, and no TX growth: `n > 30` first holds on the 31st dataPlaneCounters() call, i.e. sample
        // index 30 = nominal 15_000ms at the 500ms cadence. At index 150 (75_000ms) silence is 60_000ms < 65_000ms, and a
        // single RX advance is never VERIFIED, so the verdict stays VERIFYING through the last poll.
        val h = connectXrayKind(TransportKind.XRAY_REALITY) { n -> TransportStats.Counters(bytesReceived = if (n > 30) 512L else 0L, bytesSent = 100L, lastHandshakeEpochMillis = null) }
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()

        advanceTimeBy(XRAY_WINDOW_MILLIS)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(0, h.xray.disconnectCallCount)
        val line = h.controller.lastDataPlaneCheckDiagnostic!!
        assertTrue(line, line.startsWith("B-WL7 data-plane check: kind=XRAY_REALITY verdict=VERIFYING samples=151 "))
        assertTrue(line, line.contains(" stallWindowMs=65000 "))
        assertTrue(line, line.endsWith(" polls=151 maxPolls=150 end=WINDOW_EXHAUSTED"))
    }

    @Test
    fun `unsupported counters end the check on the first poll with COUNTERS_UNSUPPORTED and no teardown`() {
        for (stats in listOf(TransportStats.Unsupported, TransportStats.NotImplemented)) {
            runTest {
                val h = connectXrayKind(TransportKind.XRAY_REALITY) { _ -> stats }
                h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
                runCurrent()

                assertEquals(
                    "$stats",
                    "B-WL7 data-plane check: kind=XRAY_REALITY verdict=VERIFYING samples=0 rx=null tx=null stallWindowMs=65000 " +
                        "verificationWindowMs=10000 silentForMs=null polls=1 maxPolls=150 end=COUNTERS_UNSUPPORTED",
                    h.controller.lastDataPlaneCheckDiagnostic,
                )
                advanceTimeBy(XRAY_WINDOW_MILLIS)
                runCurrent()
                assertTrue("$stats", h.controller.state.value is TransportState.Connected)
                assertEquals("$stats", 0, h.xray.disconnectCallCount)
                assertTrue("$stats", h.store.recent(fingerprint()).isEmpty())
            }
        }
    }

    @Test
    fun `always-Unavailable counters run all 151 polls with no samples and end WINDOW_EXHAUSTED without teardown`() = runTest {
        val h = connectXrayKind(TransportKind.XRAY_REALITY) { _ -> TransportStats.Unavailable }
        h.controller.connect(TransportOrchestrator.Resolution.Resolved(h.xray, TransportKind.XRAY_REALITY))
        runCurrent()

        advanceTimeBy(74_000)
        runCurrent()
        assertEquals(null, h.controller.lastDataPlaneCheckDiagnostic)

        advanceTimeBy(2_000) // past index 150 = 75_000ms
        runCurrent()
        assertEquals(
            "B-WL7 data-plane check: kind=XRAY_REALITY verdict=VERIFYING samples=0 rx=null tx=null stallWindowMs=65000 " +
                "verificationWindowMs=10000 silentForMs=null polls=151 maxPolls=150 end=WINDOW_EXHAUSTED",
            h.controller.lastDataPlaneCheckDiagnostic,
        )
        assertTrue(h.controller.state.value is TransportState.Connected)
        assertEquals(0, h.xray.disconnectCallCount)
        assertTrue(h.diagnostics.snapshot.value.lastError != VpnError.DataPlaneNoTraffic)
    }

    @Test
    fun `AWG uses the 20s window and 60 polls - a TX-only session is kept at 19s and ended at 20s with that policy logged`() = runTest {
        val diagnostics = DiagnosticsStore()
        val awg = FakeVpnTransport()
        var calls = 0
        awg.statsProvider = { calls++; TransportStats.Counters(bytesReceived = 0L, bytesSent = calls * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) }
        val controller = VpnController(
            awg, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            transportObservationStore = TransportObservationStore(),
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { network },
        )
        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        advanceTimeBy(19_000)
        runCurrent()
        assertTrue("at 19s", controller.state.value is TransportState.Connected)
        assertEquals(null, controller.lastDataPlaneCheckDiagnostic)

        advanceTimeBy(1_500) // index 40 = 20_000ms
        runCurrent()
        assertTrue("at 20.5s", controller.state.value is TransportState.Error)
        assertEquals(VpnError.DataPlaneNoTraffic, diagnostics.snapshot.value.lastError)
        val line = controller.lastDataPlaneCheckDiagnostic!!
        assertTrue(line, line.startsWith("B-WL7 data-plane check: kind=AMNEZIA_WG verdict=NO_PAYLOAD samples=41 rx=0 tx="))
        assertTrue(line, line.endsWith(" stallWindowMs=20000 verificationWindowMs=10000 silentForMs=20000 polls=41 maxPolls=60 end=DECISIVE_VERDICT"))
    }
}
