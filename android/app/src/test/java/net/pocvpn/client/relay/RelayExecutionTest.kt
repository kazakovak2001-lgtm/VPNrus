package net.pocvpn.client.relay

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
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
        ingressKind = IngressKind.DIRECT_IP,
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
            ingressKind = IngressKind.CDN_FRONTED,
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
        assertEquals(candidate.ingressKind, built.ingressKind)
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

// --- B33 relay follow-up: HttpRelayEndToEndProbe.probeProfile - the narrower half [XrayCoreController]'s Relayed confirmation reuses ---

class HttpRelayEndToEndProbeTest {

    private fun plan(historyPathId: String = "ingress-1:XRAY_REALITY->exit-1:AMNEZIA_WG") = RelayedExecutionPlan(
        ingressEndpointId = EndpointId("ingress-1"),
        ingressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 2093),
        ingressTransport = TransportKind.XRAY_REALITY,
        ingressKind = IngressKind.DIRECT_IP,
        exitEndpointId = EndpointId("exit-1"),
        exitBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.60", 51820),
        exitTransport = TransportKind.AMNEZIA_WG,
        historyPathId = historyPathId,
    )

    // No real profile-issued endpoint is dialable from a plain JVM unit
    // test (see this method's own scope note below) - these cases exercise
    // the parts of probeProfile/probe that are decidable WITHOUT a live
    // round trip: a missing/refused probe URL, and (for the real-network
    // case) a genuinely refused loopback connection - proving the method
    // fails closed with a typed category and never throws out of the
    // suspend boundary, rather than asserting on a fabricated success.

    @Test
    fun `probeProfile fails closed with EXECUTION_NOT_IMPLEMENTED when the profile carries no probe URL`() = runTest {
        val profile = fakeIngressClientProfile(plan(), endToEndProbeUrl = null, endToEndProbeToken = null)

        val result = HttpRelayEndToEndProbe().probeProfile(profile)

        assertTrue(result is RelayProbeResult.Failure)
        assertEquals(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED, (result as RelayProbeResult.Failure).category)
    }

    @Test
    fun `probeProfile refuses a non-HTTPS probe URL without attempting any connection`() = runTest {
        val profile = fakeIngressClientProfile(plan(), endToEndProbeUrl = "http://127.0.0.1:1/probe", endToEndProbeToken = "t")

        val result = HttpRelayEndToEndProbe().probeProfile(profile)

        assertTrue(result is RelayProbeResult.Failure)
        assertEquals(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, (result as RelayProbeResult.Failure).category)
    }

    @Test
    fun `probeProfile fails closed (never throws) against a genuinely unreachable real endpoint`() = runTest {
        // Port 1 on loopback: a real TCP connect that is genuinely refused -
        // exercises the actual java.net.HttpURLConnection code path for
        // real, without depending on any externally-reachable host.
        val profile = fakeIngressClientProfile(plan(), endToEndProbeUrl = "https://127.0.0.1:1/probe", endToEndProbeToken = "t")

        val result = HttpRelayEndToEndProbe().probeProfile(profile)

        assertTrue("expected a typed Failure, got $result", result is RelayProbeResult.Failure)
        assertEquals(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, (result as RelayProbeResult.Failure).category)
    }

    @Test
    fun `probe(plan, profile) fails closed the same way probeProfile does for a shared, unreachable target - never a fabricated success from either`() = runTest {
        val profile = fakeIngressClientProfile(plan(), endToEndProbeUrl = "https://127.0.0.1:1/probe", endToEndProbeToken = "t")

        val narrow = HttpRelayEndToEndProbe().probeProfile(profile)
        val full = HttpRelayEndToEndProbe().probe(plan(), profile)

        assertTrue(narrow is RelayProbeResult.Failure)
        assertTrue(full is RelayProbeResult.Failure)
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
    ingressKind = plan.ingressKind,
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
