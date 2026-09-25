@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.PathCandidateBuilder
import net.pocvpn.client.reachability.PathScorer
import net.pocvpn.client.reachability.ReachabilityEvidenceSummary
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.smartconnect.AttemptStageOutcome
import net.pocvpn.client.smartconnect.AttemptTermination
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.RestrictionClassifier
import net.pocvpn.client.smartconnect.RestrictionEvidence
import net.pocvpn.client.smartconnect.TrafficProgressOutcome
import net.pocvpn.client.smartconnect.TrafficProgressSnapshot
import net.pocvpn.client.smartconnect.TrafficProgressVerdict
import net.pocvpn.client.smartconnect.TransportAttemptObservation
import net.pocvpn.client.smartconnect.TransportAttemptProtocol
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL-R1/R2/R3/R5 - real attempts through the real VpnController produce
 * TransportAttemptObservations, which feed RestrictionClassifier and, through
 * it, the single ranking authority PathScorer.
 */
class VpnControllerTransportObservationTest {

    private fun gateway() = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10", endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
    )

    private val xrayProfile = XrayProfile(
        server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    private fun controller(
        awg: FakeVpnTransport,
        scope: kotlinx.coroutines.CoroutineScope,
        store: TransportObservationStore?,
        observed: MutableList<TransportAttemptObservation> = mutableListOf(),
    ) = VpnController(
        awg, FakeClientKeyRepository(), FakeGatewayConfigurationRepository(gateway()),
        FakeReconnectManager(), DiagnosticsStore(), scope,
        xrayProfileRepository = FakeXrayProfileRepository(xrayProfile),
        transportObservationStore = store,
        onTransportObservation = { observed += it },
    )

    private fun tcpFake() = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, capabilities = TransportCapabilities.xrayRealityAdapterShell())

    @Test
    fun `AWG handshake timeout records one UDP no-response observation`() = runTest {
        val awg = FakeVpnTransport().apply { handshakeAvailable = false }
        val store = TransportObservationStore()
        val c = controller(awg, backgroundScope, store)
        c.connect(); runCurrent(); advanceTimeBy(10_000); runCurrent()
        val o = c.recentTransportObservations().single()
        assertEquals(TransportAttemptProtocol.UDP, o.protocol)
        assertEquals(AttemptStageOutcome.FAILED, o.handshake)
        assertEquals(AttemptTermination.TIMEOUT, o.termination)
        assertEquals(TrafficProgressOutcome.NO_PAYLOAD, o.progress)
        assertEquals(0L, o.bytesReceived)
        assertEquals(net.pocvpn.client.smartconnect.ProductionGateway.ID, o.destinationKey)
    }

    @Test
    fun `AWG fresh handshake records a UDP response observation`() = runTest {
        val awg = FakeVpnTransport().apply { statsBytesReceived = 148 }
        val store = TransportObservationStore()
        val c = controller(awg, backgroundScope, store)
        c.connect(); runCurrent()
        val o = c.recentTransportObservations().single()
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.handshake)
        assertEquals(148L, o.bytesReceived)
    }

    @Test
    fun `a confirmed TCP-only (Xray) attempt records exactly one TCP observation, later state changes add nothing`() = runTest {
        val xray = tcpFake()
        val store = TransportObservationStore()
        val c = controller(FakeVpnTransport(), backgroundScope, store)
        c.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY)); runCurrent()
        xray.forceState(TransportState.Error("later runtime failure")); runCurrent()
        val o = c.recentTransportObservations().single()
        assertEquals(TransportAttemptProtocol.TCP, o.protocol)
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.connect)
        assertEquals(AttemptStageOutcome.SUCCEEDED, o.handshake)
    }

    @Test
    fun `an unconfirmed Xray attempt records a stage-unknown observation, a local failure records nothing`() = runTest {
        val store = TransportObservationStore()
        val xray = tcpFake().apply { connectGate = kotlinx.coroutines.CompletableDeferred() }
        val c = controller(FakeVpnTransport(), backgroundScope, store)
        backgroundScope.launchConnect(c, xray); runCurrent()
        xray.forceState(TransportState.Error("remote handshake not confirmed", failureKind = TransportFailureKind.REMOTE_UNCONFIRMED)); runCurrent()
        val o = c.recentTransportObservations().single()
        assertEquals(AttemptStageOutcome.NOT_OBSERVED, o.connect)
        assertEquals(AttemptStageOutcome.NOT_OBSERVED, o.handshake)

        val store2 = TransportObservationStore()
        val xray2 = tcpFake().apply { connectGate = kotlinx.coroutines.CompletableDeferred() }
        val c2 = controller(FakeVpnTransport(), backgroundScope, store2)
        backgroundScope.launchConnect(c2, xray2); runCurrent()
        xray2.forceState(TransportState.Error("Xray profile not ready")); runCurrent()
        assertTrue(c2.recentTransportObservations().isEmpty())
    }

    private fun kotlinx.coroutines.CoroutineScope.launchConnect(c: VpnController, t: FakeVpnTransport) =
        launch { c.connect(TransportOrchestrator.Resolution.Resolved(t, TransportKind.XRAY_REALITY)) }

    @Test
    fun `no store wired - nothing recorded, nothing read (pre-B-WL-R1 behavior)`() = runTest {
        val awg = FakeVpnTransport().apply { handshakeAvailable = false }
        val observed = mutableListOf<TransportAttemptObservation>()
        val c = controller(awg, backgroundScope, store = null, observed = observed)
        c.connect(); runCurrent(); advanceTimeBy(10_000); runCurrent()
        assertTrue(c.recentTransportObservations().isEmpty())
        assertTrue(observed.isEmpty())
    }

    @Test
    fun `traffic-progress verdicts update trafficProgress and record one observation per verdict change`() = runTest {
        val xray = tcpFake()
        val store = TransportObservationStore()
        val c = controller(FakeVpnTransport(), backgroundScope, store)
        c.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY)); runCurrent()
        xray.trafficProgress.tryEmit(TrafficProgressSnapshot(TrafficProgressVerdict.VERIFYING, 100, 50)); runCurrent()
        xray.trafficProgress.tryEmit(TrafficProgressSnapshot(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, 9_000, 6_000)); runCurrent()
        xray.trafficProgress.tryEmit(TrafficProgressSnapshot(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, 9_000, 7_000)); runCurrent()
        assertEquals(TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD, c.trafficProgress.value)
        val progress = c.recentTransportObservations().filter { it.progress == TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD }
        assertEquals(1, progress.size)
        assertEquals(9_000L, progress.single().bytesReceived)
        c.disconnect(); runCurrent()
        assertEquals(null, c.trafficProgress.value)
    }

    @Test
    fun `runtime pipeline - AWG timeout then confirmed Xray - classifier says POSSIBLE_UDP_FILTERING and PathScorer re-orders the next attempt`() = runTest {
        val awg = FakeVpnTransport().apply { handshakeAvailable = false }
        val store = TransportObservationStore()
        val c = controller(awg, backgroundScope, store)
        // Attempt A (UDP): times out.
        c.connect(); runCurrent(); advanceTimeBy(10_000); runCurrent()
        // Attempt B (TCP/Xray): confirmed.
        c.connect(TransportOrchestrator.Resolution.Resolved(tcpFake(), TransportKind.XRAY_REALITY)); runCurrent()

        val profile = NetworkProfile(
            type = NetworkType.CELLULAR, validatedInternet = true, metered = true, roaming = false,
            captivePortal = false, ipv4Available = true, ipv6Available = false, vpnActive = true, generation = 1,
        )
        val evidence = RestrictionEvidence(
            profile, c.state.value, awgHandshakeFresh = false, gatewayHttpsReachable = true, diverseInternetReachable = null,
            transportObservations = c.recentTransportObservations(),
        )
        val assessment = RestrictionClassifier.assess(evidence)
        assertEquals(RestrictionClass.POSSIBLE_UDP_FILTERING, assessment.classification)

        // The next attempt's ranking, through the one ranking authority:
        // NORMAL keeps AWG first; the observed UDP filtering lifts the
        // restrictive-network TCP transport first and drops AWG last.
        assertEquals(TransportKind.AMNEZIA_WG, rank(RestrictionClass.UNKNOWN).first())
        assertEquals(
            listOf(TransportKind.XRAY_REALITY_XHTTP, TransportKind.XRAY_REALITY, TransportKind.AMNEZIA_WG),
            rank(assessment.classification),
        )
    }

    private fun rank(restriction: RestrictionClass): List<TransportKind> {
        val kinds = listOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.XRAY_REALITY_XHTTP)
        val caps = mapOf(
            TransportKind.AMNEZIA_WG to TransportCapabilities.amneziaWg(),
            TransportKind.XRAY_REALITY to TransportCapabilities.xrayRealityAdapterShell(),
            TransportKind.XRAY_REALITY_XHTTP to TransportCapabilities.xrayRealityXhttpAdapterShell(),
        )
        val registry = TransportRegistry.build(kinds.map { k -> TransportDescriptor(k, TransportStatus.AVAILABLE, caps.getValue(k), factory = { FakeVpnTransport(kind = k) }) })
        val endpoint = EndpointDescriptor(
            EndpointId("gw1"), setOf(EndpointRole.GATEWAY), "eu", "p",
            transports = kinds.map { EndpointTransportBinding(it, "203.0.113.1", 443) },
        )
        return PathScorer.rank(
            kinds.map { k ->
                val reach = EndpointReachability(endpoint.id, k, ReachabilityState.REACHABLE, evidence = ReachabilityEvidenceSummary(TransportHealthState.UNKNOWN, null, null, true, restriction))
                PathScorer.score(PathCandidateBuilder.buildDirect(endpoint, k, reach)!!, registry, caps.getValue(k), TransportHealth(state = TransportHealthState.UNKNOWN), null, false)
            },
        ).map { it.candidate.transport }
    }
}
