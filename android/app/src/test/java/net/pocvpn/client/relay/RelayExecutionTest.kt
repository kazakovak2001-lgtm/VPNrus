package net.pocvpn.client.relay

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayExecutionTest {

    private fun plan(
        ingressTransport: TransportKind = TransportKind.TLS_TCP,
        exitTransport: TransportKind = TransportKind.AMNEZIA_WG,
    ) = RelayedExecutionPlan(
        ingressEndpointId = EndpointId("ingress-1"),
        ingressBinding = EndpointTransportBinding(ingressTransport, "203.0.113.50", 443),
        ingressTransport = ingressTransport,
        exitEndpointId = EndpointId("exit-1"),
        exitBinding = EndpointTransportBinding(exitTransport, "203.0.113.60", 51820),
        exitTransport = exitTransport,
        historyPathId = "ingress-1:$ingressTransport->exit-1:$exitTransport",
    )

    @Test
    fun `RelayedExecutionPlan from a RelayAttemptCandidate pins the exact same fields - never re-derived`() {
        val candidate = AutoGatewaySelector.RelayAttemptCandidate(
            ingressEndpointId = EndpointId("ingress-1"),
            exitEndpointId = EndpointId("exit-1"),
            ingressTransport = TransportKind.TLS_TCP,
            exitTransport = TransportKind.AMNEZIA_WG,
            ingressBinding = EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.50", 443),
            exitBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.60", 51820),
            ingressRegion = "ru",
            exitRegion = "de",
            score = 1_000_000L,
            reasons = listOf("ENDPOINT_REACHABLE"),
            historyPathId = "ingress-1:TLS_TCP->exit-1:AMNEZIA_WG",
        )
        val built = RelayedExecutionPlan.from(candidate)
        assertEquals(candidate.ingressEndpointId, built.ingressEndpointId)
        assertEquals(candidate.ingressBinding, built.ingressBinding)
        assertEquals(candidate.ingressTransport, built.ingressTransport)
        assertEquals(candidate.exitEndpointId, built.exitEndpointId)
        assertEquals(candidate.exitBinding, built.exitBinding)
        assertEquals(candidate.exitTransport, built.exitTransport)
        assertEquals(candidate.historyPathId, built.historyPathId)
    }

    // --- B24 task requirement H: readiness fail-closed by construction ---

    @Test
    fun `Success is only ever END_TO_END_DATA_PLANE_OK - structurally, not by convention`() {
        val success = RelayAttemptOutcome.Success(plan())
        assertEquals(RelayReadinessStage.END_TO_END_DATA_PLANE_OK, success.highestStageReached)
        assertTrue(success.isHealthy)
    }

    @Test
    fun `a Failure can never claim END_TO_END_DATA_PLANE_OK as its highest stage`() {
        assertThrows(IllegalArgumentException::class.java) {
            RelayAttemptOutcome.Failure(
                plan = plan(),
                highestStageReached = RelayReadinessStage.END_TO_END_DATA_PLANE_OK,
                category = RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED,
            )
        }
    }

    @Test
    fun `an ingress handshake success alone (no upstream+data-plane proof) is never healthy`() {
        val outcome = RelayAttemptOutcome.Failure(
            plan = plan(),
            highestStageReached = RelayReadinessStage.INGRESS_HANDSHAKE_OK,
            category = RelayFailureCategory.UPSTREAM_EXIT_HANDSHAKE_FAILED,
        )
        assertFalse(outcome.isHealthy)
    }

    @Test
    fun `an upstream exit handshake success alone (no confirmed data plane) is still never healthy`() {
        val outcome = RelayAttemptOutcome.Failure(
            plan = plan(),
            highestStageReached = RelayReadinessStage.UPSTREAM_EXIT_HANDSHAKE_OK,
            category = RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED,
        )
        assertFalse(outcome.isHealthy)
    }

    // --- B24 task requirement I: correct typed failure per layer ---

    @Test
    fun `every typed RelayFailureCategory is representable as a Failure outcome`() {
        RelayFailureCategory.entries.forEach { category ->
            val outcome = RelayAttemptOutcome.Failure(plan(), highestStageReached = null, category = category)
            assertFalse(outcome.isHealthy)
            assertEquals(category, outcome.category)
        }
    }

    // --- B24 - NotProvisionedRelayIngressResolver: no fake relay success ---

    @Test
    fun `NotProvisionedRelayIngressResolver always reports NotProvisioned with EXECUTION_NOT_IMPLEMENTED - never a fabricated transport`() = runTest {
        val resolution = NotProvisionedRelayIngressResolver.resolve(plan())
        assertTrue(resolution is RelayIngressResolution.NotProvisioned)
        val notProvisioned = resolution as RelayIngressResolution.NotProvisioned
        assertEquals(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED, notProvisioned.category)
    }

    @Test
    fun `ingress and exit transports remain independently pinned when the plan is built`() {
        val p = plan(ingressTransport = TransportKind.XRAY_REALITY, exitTransport = TransportKind.TLS_TCP)
        assertEquals(TransportKind.XRAY_REALITY, p.ingressBinding.kind)
        assertEquals(TransportKind.TLS_TCP, p.exitBinding.kind)
        assertTrue(p.ingressTransport != p.exitTransport)
    }

    // --- B24 review fix (PR #38, round 3) - RelayIngressResolver is a preparation boundary only ---

    @Test
    fun `RelayIngressResolution carries no state of its own - Resolved is only a transport, a kind, and the matched profile, never an outcome`() {
        val p = plan(ingressTransport = TransportKind.TLS_TCP)
        val transport = net.pocvpn.client.vpn.FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val profile = fakeIngressClientProfile(p)
        val resolution = RelayIngressResolution.Resolved(transport, TransportKind.TLS_TCP, profile)
        // Structurally: Resolved has no `outcome`/`isHealthy`/`state` field
        // to read - the only way to learn what happened is to actually
        // dial `resolution.transport` through the real
        // TransportOrchestrator/VpnController path and observe REAL
        // controller.state, exactly like a Direct candidate.
        assertEquals(transport, resolution.transport)
        assertEquals(TransportKind.TLS_TCP, resolution.kind)
        assertEquals(profile, resolution.profile)
    }
}

/** Shared test fixture - a structurally-valid [IngressClientProfile] matching [plan]. */
internal fun fakeIngressClientProfile(
    plan: RelayedExecutionPlan,
    profileVersion: Int = 1,
    issuedAtEpochMillis: Long = 0L,
    expiresAtEpochMillis: Long? = null,
    endToEndProbeUrl: String? = "https://exit.example/v1/relay-health",
    endToEndProbeToken: String? = "test-token",
): IngressClientProfile = IngressClientProfile(
    ingressEndpointId = plan.ingressEndpointId,
    ingressBinding = plan.ingressBinding,
    transport = plan.ingressTransport,
    realityProfile = if (plan.ingressTransport == TransportKind.XRAY_REALITY) {
        net.pocvpn.client.identity.XrayProfile(
            server = plan.ingressBinding.host,
            serverPort = plan.ingressBinding.port,
            uuid = "11111111-1111-1111-1111-111111111111",
            flow = "",
            serverName = "example.com",
            fingerprint = "chrome",
            realityPublicKey = "A".repeat(43),
            shortId = "ab",
        )
    } else {
        null
    },
    tlsProfile = if (plan.ingressTransport == TransportKind.TLS_TCP) {
        net.pocvpn.client.identity.XrayTlsProfile(
            server = plan.ingressBinding.host,
            serverPort = plan.ingressBinding.port,
            uuid = "22222222-2222-2222-2222-222222222222",
            serverName = "example.com",
            fingerprint = "chrome",
        )
    } else {
        null
    },
    profileVersion = profileVersion,
    issuedAtEpochMillis = issuedAtEpochMillis,
    expiresAtEpochMillis = expiresAtEpochMillis,
    endToEndProbeUrl = endToEndProbeUrl,
    endToEndProbeToken = endToEndProbeToken,
)
