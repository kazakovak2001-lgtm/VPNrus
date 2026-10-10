@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
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
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Hysteria2Profile
import net.pocvpn.client.reachability.withHysteria2Profile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
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

    private class Harness(
        val controller: VpnController,
        val xray: FakeVpnTransport,
        val diagnostics: DiagnosticsStore,
        val store: TransportObservationStore,
        val reconnect: FakeReconnectManager,
    )

    private fun TestScope.connectXray(dataPlane: (Int) -> TransportStats): Harness {
        val diagnostics = DiagnosticsStore()
        val store = TransportObservationStore()
        val reconnect = FakeReconnectManager()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            reconnect, diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(XRAY_PROFILE),
            transportObservationStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { network },
        )
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        var polls = 0
        xray.dataPlaneProvider = { polls++; dataPlane(polls) }
        return Harness(controller, xray, diagnostics, store, reconnect)
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

    // --- M1: counters alone cannot tell a dead exit from a healthy upload-only flow ---
    // Xray counts VLESS stream bytes: TCP ACKs never cross the tunnel and the
    // VLESS server sends nothing until the destination replies, so an upload
    // with no reply has exactly the `stalled` shape below. Before ending such
    // a session the controller asks once whether the exit still reaches an
    // INDEPENDENT destination (another gateway). Timeline: the stall is
    // decisive at 20 s; after a REACHED probe the counters are read again (the
    // probe's own bytes included) and one more stall window is watched from
    // that post-probe baseline, i.e. until 40 s.

    private val stalled: (Int) -> TransportStats = { n -> TransportStats.Counters(bytesReceived = 512L, bytesSent = 1_000L + n * 300L, lastHandshakeEpochMillis = null) }

    private fun assertNoDataPlaneFailure(h: Harness) {
        assertNotEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        val state = h.controller.state.value
        assertTrue("unexpected $state", state !is TransportState.Error)
    }

    private fun assertDataPlaneFailure(h: Harness) {
        val state = h.controller.state.value
        assertTrue("unexpected $state", state is TransportState.Error)
        assertEquals(TransportFailureKind.REMOTE_UNCONFIRMED, (state as TransportState.Error).failureKind)
        assertEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
    }

    /**
     * Behaves like the `:xray` VLESS-outbound totals the controller reads via
     * dataPlaneCounters(): cumulative, driven by (virtual) time, and - like the
     * real core, whose measureDelay dials through the SAME counted outbound
     * (core.Dial -> outbound Handler.Dial -> CounterConnection) - the egress
     * probe's own TLS round trip to the other gateway lands in them.
     */
    private class XrayCounters(private val clock: () -> Long) {
        var uploading = true
        var replying = false
        var unavailable = false
        var reads = 0
            private set
        private var tick = 0L
        private var userSent = 1_000L
        private var userReceived = 512L // B33 confirmation bytes
        private var probeSent = 0L
        private var probeReceived = 0L

        fun read(): TransportStats {
            reads++
            val now = clock()
            val elapsedTicks = (now - tick) / 500L
            tick += elapsedTicks * 500L
            if (uploading) userSent += elapsedTicks * 300L
            if (replying) userReceived += elapsedTicks * 900L
            if (unavailable) return TransportStats.Unavailable
            return TransportStats.Counters(bytesReceived = userReceived + probeReceived, bytesSent = userSent + probeSent, lastHandshakeEpochMillis = null)
        }

        /** The probe's ClientHello/request up, certificate chain + 200 down. */
        fun probeRoundTrip() {
            probeSent += 700L
            probeReceived += 4_096L
        }
    }

    private fun TestScope.connectXray(counters: XrayCounters): Harness = connectXray { _ -> counters.read() }

    private fun TestScope.xrayCounters() = XrayCounters { currentTime }

    @Test
    fun `healthy upload - probe bytes then real replies - session stays, recorded from real traffic`() = runTest {
        val counters = xrayCounters()
        val h = connectXray(counters)
        h.xray.egressProber = {
            counters.probeRoundTrip()
            counters.replying = true // the destination starts answering after the probe
            IndependentEgressProbeResult.REACHED
        }
        start(h)

        advanceTimeBy(45_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertNoDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
        assertEquals(0, h.xray.disconnectCallCount)
        assertEquals(TrafficProgressOutcome.SUSTAINED, h.store.recent(fingerprint()).single().progress)
    }

    @Test
    fun `probe bytes are not user progress - upload with no reply after a reached probe ends at the post-probe stall window`() = runTest {
        val counters = xrayCounters()
        val h = connectXray(counters)
        h.xray.egressProber = { counters.probeRoundTrip(); IndependentEgressProbeResult.REACHED }
        start(h)

        // Probe at 20 s; the probe completing ends nothing.
        advanceTimeBy(21_000)
        runCurrent()
        assertEquals(1, h.xray.egressProbeCallCount)
        assertTrue(h.controller.state.value is TransportState.Connected)

        // Still within one stall window of the post-probe baseline (20 s -> 40 s).
        advanceTimeBy(18_500)
        runCurrent()
        assertTrue(h.controller.state.value is TransportState.Connected)

        advanceTimeBy(1_000)
        runCurrent()
        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, h.store.recent(fingerprint()).single().progress)
    }

    @Test
    fun `nothing moves after the post-probe baseline - the window ends IDLE, bounded, not VERIFYING`() = runTest {
        val counters = xrayCounters()
        val h = connectXray(counters)
        h.xray.egressProber = {
            counters.probeRoundTrip()
            counters.uploading = false
            IndependentEgressProbeResult.REACHED
        }
        start(h)

        advanceTimeBy(120_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Connected)
        assertNoDataPlaneFailure(h)
        // 41 reads up to the probe (0..20 s), 1 post-probe baseline read, then
        // exactly one stall window (40 reads, 20.5..40 s) and no more.
        assertEquals(82, counters.reads)
        assertEquals(1, h.xray.egressProbeCallCount)
        // The window concluded (IDLE -> NOT_OBSERVED), it did not run out undecided.
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, h.store.recent(fingerprint()).single().progress)
    }

    @Test
    fun `a reached probe without a fresh post-probe sample keeps the original failure`() = runTest {
        val counters = xrayCounters()
        val h = connectXray(counters)
        h.xray.egressProber = {
            counters.probeRoundTrip()
            counters.unavailable = true // :xray stops answering the counter query
            IndependentEgressProbeResult.REACHED
        }
        start(h)

        advanceTimeBy(21_000)
        runCurrent()

        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
    }

    @Test
    fun `a reconnect taking ownership right before the post-probe sample leaves the new session alone`() = runTest {
        val counters = xrayCounters()
        val h = connectXray(counters)
        var readsAtReconnect = -1
        h.xray.egressProber = {
            counters.probeRoundTrip()
            readsAtReconnect = counters.reads
            h.reconnect.triggerUnderlyingNetworkChanged()
            IndependentEgressProbeResult.REACHED
        }
        start(h)

        advanceTimeBy(120_000)
        runCurrent()

        assertNoDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
        // The superseded sampler takes at most its post-probe read, then stops:
        // no further polling, no observation written for the new session.
        assertTrue("reads ${counters.reads} vs $readsAtReconnect", counters.reads <= readsAtReconnect + 1)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `dead gateway egress - independent probe not reached - session ends with DataPlaneNoTraffic`() = runTest {
        val h = connectXray(stalled)
        h.xray.egressProber = { IndependentEgressProbeResult.NOT_REACHED }
        start(h)

        advanceTimeBy(21_000)
        runCurrent()

        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, h.store.recent(fingerprint()).single().progress)
    }

    @Test
    fun `no independent target (UNAVAILABLE) keeps the existing failure`() = runTest {
        val h = connectXray(stalled)
        h.xray.egressProber = { IndependentEgressProbeResult.UNAVAILABLE }
        start(h)

        advanceTimeBy(21_000)
        runCurrent()

        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
    }

    @Test
    fun `a probe that never answers is bounded at 10 s and keeps the failure`() = runTest {
        val h = connectXray(stalled)
        val never = CompletableDeferred<IndependentEgressProbeResult>()
        h.xray.egressProber = { never.await() }
        start(h)

        advanceTimeBy(29_000)
        runCurrent()
        assertEquals(1, h.xray.egressProbeCallCount)
        assertTrue(h.controller.state.value is TransportState.Connected)

        advanceTimeBy(1_500)
        runCurrent()
        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
    }

    @Test
    fun `a probe that throws counts as not reached and keeps the failure`() = runTest {
        val h = connectXray(stalled)
        h.xray.egressProber = { throw IllegalStateException("receiver not registered") }
        start(h)

        advanceTimeBy(21_000)
        runCurrent()

        assertDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
    }

    @Test
    fun `a user disconnect during the probe wins - no stale failure afterwards`() = runTest {
        val h = connectXray(stalled)
        val answer = CompletableDeferred<IndependentEgressProbeResult>()
        h.xray.egressProber = { answer.await() }
        start(h)
        advanceTimeBy(20_500)
        runCurrent()
        assertEquals(1, h.xray.egressProbeCallCount)

        h.controller.disconnect()
        runCurrent()
        answer.complete(IndependentEgressProbeResult.NOT_REACHED)
        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(h.controller.state.value is TransportState.Disconnected)
        assertNotEquals(VpnError.DataPlaneNoTraffic, h.diagnostics.snapshot.value.lastError)
        assertEquals(1, h.xray.disconnectCallCount)
        assertTrue(h.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `a reconnect that takes ownership during the probe makes its result inert`() = runTest {
        val h = connectXray(stalled)
        val answer = CompletableDeferred<IndependentEgressProbeResult>()
        h.xray.egressProber = { answer.await() }
        start(h)
        advanceTimeBy(20_500)
        runCurrent()
        assertEquals(1, h.xray.egressProbeCallCount)

        // Xray restarts its session on a network change: a new reconnect
        // generation owns the controller while the old probe is in flight.
        h.reconnect.triggerUnderlyingNetworkChanged()
        runCurrent()
        answer.complete(IndependentEgressProbeResult.NOT_REACHED)
        advanceTimeBy(31_000)
        runCurrent()

        assertNoDataPlaneFailure(h)
        assertEquals(1, h.xray.egressProbeCallCount)
    }

    @Test
    fun `normal progress, idle and unavailable samples never trigger a probe`() = runTest {
        val working = connectXray { n -> TransportStats.Counters(bytesReceived = n * 900L, bytesSent = n * 300L, lastHandshakeEpochMillis = null) }
        val idle = connectXray { _ -> TransportStats.Counters(bytesReceived = 512L, bytesSent = 300L, lastHandshakeEpochMillis = null) }
        val unavailable = connectXray { _ -> TransportStats.Unavailable }
        listOf(working, idle, unavailable).forEach { h -> h.xray.egressProber = { fail("probe must not run"); IndependentEgressProbeResult.NOT_REACHED } }
        start(working)
        start(idle)
        start(unavailable)

        advanceTimeBy(31_000)
        runCurrent()

        listOf(working, idle, unavailable).forEach { h ->
            assertEquals(0, h.xray.egressProbeCallCount)
            assertTrue(h.controller.state.value is TransportState.Connected)
        }
        assertTrue(unavailable.store.recent(fingerprint()).isEmpty())
    }

    @Test
    fun `Hysteria2 with Unsupported counters is never probed or failed`() = runTest {
        val diagnostics = DiagnosticsStore()
        val hysteria = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        hysteria.dataPlaneProvider = { TransportStats.Unsupported }
        hysteria.egressProber = { fail("probe must not run"); IndependentEgressProbeResult.NOT_REACHED }
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(gateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            hysteria2Transport = hysteria,
        )
        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                hysteria, TransportKind.HYSTERIA2,
                endpointId = EndpointId("stockholm"),
                endpointTransportBinding = EndpointTransportBinding(kind = TransportKind.HYSTERIA2, host = "16.170.208.231", port = 443)
                    .withHysteria2Profile(Hysteria2Profile(sni = "origin-sthlm.aknova.pp.ua", obfuscationMode = "NONE")),
            ),
        )
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(0, hysteria.egressProbeCallCount)
        assertEquals(0, hysteria.disconnectCallCount)
        assertNotEquals(VpnError.DataPlaneNoTraffic, diagnostics.snapshot.value.lastError)
    }
}
