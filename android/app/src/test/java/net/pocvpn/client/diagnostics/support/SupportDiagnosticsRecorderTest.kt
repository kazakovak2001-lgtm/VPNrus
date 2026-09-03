package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B29 (task K) - the recorder assembles ONE real [DiagnosticSession] per
 * connection attempt, purely from typed inputs the caller already computed
 * (never re-deriving anything itself).
 */
class SupportDiagnosticsRecorderTest {

    private fun context(
        raw: RestrictionClass = RestrictionClass.UNKNOWN,
        stabilized: RestrictionClass = RestrictionClass.UNKNOWN,
    ) = SupportDiagnosticsRecorder.StartContext(
        networkType = NetworkType.WIFI,
        networkValidatedInternet = true,
        networkCaptivePortal = false,
        networkIpv4Available = true,
        networkIpv6Available = false,
        networkFingerprintId = "abc123fingerprint",
        rawRestrictionClass = raw,
        stabilizedRestrictionClass = stabilized,
        routingMode = RoutingMode.FULL_VPN,
        gatewaySelectionMode = GatewaySelectionMode.AUTO,
    )

    private fun newRecorder(store: DiagnosticSessionStore = InMemoryDiagnosticSessionStore()) =
        SupportDiagnosticsRecorder(store, appVersionName = "1.2.3", appVersionCode = 42L)

    @Test
    fun `a successful DIRECT session is recorded with the correct path and transport kind`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordManifestSourceSelected("signed-manifest")
        recorder.recordCandidateRanked(2)
        recorder.recordCandidateAttemptStarted(PathKind.DIRECT, TransportKind.AMNEZIA_WG)
        recorder.recordEndpointReachabilityResult(ReachabilityState.REACHABLE)
        recorder.recordTransportStart(TransportKind.AMNEZIA_WG)
        recorder.recordTransportHandshakeResult(success = true)
        recorder.finishProtected()

        val session = store.recent().single()
        assertEquals(DiagnosticOutcome.PROTECTED, session.outcome)
        assertNull(session.failureReason)
        assertEquals(PathKind.DIRECT, session.selectedPathKind)
        assertEquals(TransportKind.AMNEZIA_WG, session.selectedTransportKind)
        assertTrue(session.events.any { it.type == DiagnosticEventType.VPN_PROTECTED })
        assertTrue(session.events.any { it.type == DiagnosticEventType.PATH_SUCCEEDED })
    }

    @Test
    fun `a successful CHAIN_DIRECT session records the relayed path kind and transport`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.CHAIN_DIRECT, TransportKind.TLS_TCP)
        recorder.recordRelayActivationRequired()
        recorder.recordRelayActivationResult(IngressActivationOutcome.Saved(fakeProfile()))
        recorder.recordDataPlaneReadinessResult(RelayReadinessStage.END_TO_END_DATA_PLANE_OK)
        recorder.recordRelayEndToEndProofResult(success = true, category = null)
        recorder.finishProtected()

        val session = store.recent().single()
        assertEquals(DiagnosticOutcome.PROTECTED, session.outcome)
        assertEquals(PathKind.CHAIN_DIRECT, session.selectedPathKind)
        assertEquals(TransportKind.TLS_TCP, session.selectedTransportKind)
    }

    @Test
    fun `a successful CHAIN_CDN session records the CDN-fronted path kind`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.CHAIN_CDN, TransportKind.TLS_TCP)
        recorder.recordDataPlaneReadinessResult(RelayReadinessStage.END_TO_END_DATA_PLANE_OK)
        recorder.finishProtected()

        val session = store.recent().single()
        assertEquals(DiagnosticOutcome.PROTECTED, session.outcome)
        assertEquals(PathKind.CHAIN_CDN, session.selectedPathKind)
    }

    @Test
    fun `a RestrictedNetworkNoViableRelay session is recorded as a failed, correctly-reasoned outcome`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context(raw = RestrictionClass.POSSIBLE_HARD_WHITELIST, stabilized = RestrictionClass.POSSIBLE_HARD_WHITELIST))
        recorder.finishRestrictedNetworkExhaustion()

        val session = store.recent().single()
        assertEquals(DiagnosticOutcome.FAILED, session.outcome)
        assertEquals(DiagnosticFailureReason.RESTRICTED_NETWORK_NO_VIABLE_RELAY, session.failureReason)
        assertTrue(session.events.any { it.type == DiagnosticEventType.RESTRICTED_NETWORK_EXHAUSTION })
    }

    @Test
    fun `a transport handshake failure is recorded with the PROTOCOL_OR_TRANSPORT_BLOCKED reason`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.DIRECT, TransportKind.AMNEZIA_WG)
        recorder.recordTransportStart(TransportKind.AMNEZIA_WG)
        recorder.recordTransportHandshakeResult(success = false)
        recorder.finishFailed(DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED)

        val session = store.recent().single()
        assertEquals(DiagnosticOutcome.FAILED, session.outcome)
        assertEquals(DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED, session.failureReason)
        assertTrue(session.events.any { it.type == DiagnosticEventType.TRANSPORT_HANDSHAKE_RESULT && it.tags["success"] == "false" })
    }

    @Test
    fun `a data-plane readiness failure is recorded distinctly from a handshake failure`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.CHAIN_DIRECT, TransportKind.TLS_TCP)
        recorder.recordDataPlaneReadinessResult(RelayReadinessStage.INGRESS_HANDSHAKE_OK)
        recorder.finishFailed(DiagnosticFailureReason.DATA_PLANE_NOT_READY)

        val session = store.recent().single()
        assertEquals(DiagnosticFailureReason.DATA_PLANE_NOT_READY, session.failureReason)
        assertTrue(session.events.any { it.type == DiagnosticEventType.DATA_PLANE_READINESS_RESULT && it.tags["stage"] == "INGRESS_HANDSHAKE_OK" })
    }

    @Test
    fun `a relay end-to-end proof failure maps its RelayFailureCategory into the closed taxonomy`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.CHAIN_CDN, TransportKind.TLS_TCP)
        recorder.recordRelayEndToEndProofResult(success = false, category = RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED)
        recorder.finishFailed(DiagnosticFailureReason.RELAY_END_TO_END_PROOF_FAILED)

        val session = store.recent().single()
        assertEquals(DiagnosticFailureReason.RELAY_END_TO_END_PROOF_FAILED, session.failureReason)
        val proofEvent = session.events.single { it.type == DiagnosticEventType.RELAY_END_TO_END_PROOF_RESULT }
        assertEquals("false", proofEvent.tags["success"])
        assertEquals("RELAY_END_TO_END_PROOF_FAILED", proofEvent.tags["failureReason"])
    }

    @Test
    fun `activation and control-plane failures are represented with their own typed reasons`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)

        recorder.startSession(context())
        recorder.recordRelayActivationRequired()
        recorder.recordRelayActivationResult(IngressActivationOutcome.AuthorizationFailed)
        recorder.finishFailed(DiagnosticFailureReason.ACTIVATION_FAILED)
        val activationSession = store.recent().single()
        assertEquals(DiagnosticFailureReason.ACTIVATION_FAILED, activationSession.failureReason)
        val activationEvent = activationSession.events.single { it.type == DiagnosticEventType.RELAY_ACTIVATION_RESULT }
        assertEquals("false", activationEvent.tags["success"])
        assertEquals("ACTIVATION_FAILED", activationEvent.tags["failureReason"])

        recorder.startSession(context())
        recorder.recordControlPlaneFailure(DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE)
        recorder.finishFailed(DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE)
        val controlPlaneSession = store.recent().first()
        assertEquals(DiagnosticOutcome.FAILED, controlPlaneSession.outcome)
        assertEquals(DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE, controlPlaneSession.failureReason)
        assertTrue(controlPlaneSession.events.any { it.type == DiagnosticEventType.CONTROL_PLANE_FAILURE })
    }

    @Test
    fun `raw vs stabilized RestrictionClass are both recorded from the SAME start context, never independently recomputed`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context(raw = RestrictionClass.GATEWAY_HTTPS_UNREACHABLE, stabilized = RestrictionClass.POSSIBLE_HARD_WHITELIST))
        recorder.finishRestrictedNetworkExhaustion()

        val session = store.recent().single()
        assertEquals(RestrictionClass.GATEWAY_HTTPS_UNREACHABLE, session.rawRestrictionClass)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, session.stabilizedRestrictionClass)
        val classifiedEvent = session.events.single { it.type == DiagnosticEventType.RESTRICTION_CLASSIFIED }
        val stabilizedEvent = session.events.single { it.type == DiagnosticEventType.RESTRICTION_STABILIZED }
        assertEquals("GATEWAY_HTTPS_UNREACHABLE", classifiedEvent.tags["restrictionClass"])
        assertEquals("POSSIBLE_HARD_WHITELIST", stabilizedEvent.tags["restrictionClass"])
    }

    @Test
    fun `the selected path and transport kind reflect the LAST candidate attempt actually started, not merely the first ranked`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.DIRECT, TransportKind.AMNEZIA_WG)
        recorder.finishFailed(DiagnosticFailureReason.GATEWAY_UNREACHABLE)

        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.DIRECT, TransportKind.AMNEZIA_WG)
        // Direct failed; Auto's bounded failover moves to the next ranked candidate - a real relay attempt.
        recorder.recordCandidateAttemptStarted(PathKind.CHAIN_DIRECT, TransportKind.TLS_TCP)
        recorder.finishProtected()

        val secondSession = store.recent().first()
        assertEquals(PathKind.CHAIN_DIRECT, secondSession.selectedPathKind)
        assertEquals(TransportKind.TLS_TCP, secondSession.selectedTransportKind)
    }

    @Test
    fun `a per-session event count is bounded - a runaway retry loop cannot grow one session unboundedly`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        repeat(DiagnosticSession.MAX_EVENTS_PER_SESSION * 2) {
            recorder.recordEndpointReachabilityResult(ReachabilityState.UNKNOWN)
        }
        recorder.finishProtected()

        val session = store.recent().single()
        assertTrue(session.events.size <= DiagnosticSession.MAX_EVENTS_PER_SESSION)
    }

    @Test
    fun `starting a new session abandons a previous unfinished one without persisting it`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.startSession(context())
        recorder.recordCandidateAttemptStarted(PathKind.DIRECT, TransportKind.AMNEZIA_WG)
        // Never finished (no terminal call) - then a new attempt starts.
        recorder.startSession(context())
        recorder.finishProtected()

        assertEquals(1, store.recent().size)
    }

    @Test
    fun `finishDisconnected before any session ever started is a safe no-op`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = newRecorder(store)
        recorder.finishDisconnected()
        assertTrue(store.recent().isEmpty())
    }

    private fun fakeProfile(): net.pocvpn.client.relay.IngressClientProfile = net.pocvpn.client.relay.IngressClientProfile(
        ingressEndpointId = net.pocvpn.client.reachability.EndpointId("ru-ingress-1"),
        ingressBinding = net.pocvpn.client.reachability.EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.50", 443),
        transport = TransportKind.TLS_TCP,
        ingressKind = net.pocvpn.client.reachability.IngressKind.DIRECT_IP,
        realityProfile = null,
        tlsProfile = net.pocvpn.client.identity.XrayTlsProfile(
            server = "203.0.113.50", serverPort = 443, uuid = "11111111-1111-1111-1111-111111111111",
            serverName = "example.com", fingerprint = "chrome",
        ),
        profileVersion = 1,
        issuedAtEpochMillis = 0L,
        expiresAtEpochMillis = null,
        endToEndProbeUrl = "https://exit.example.com/v1/relay-health",
        endToEndProbeToken = "token",
    )
}
