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

    // --- B24 - NotProvisionedRelayIngressDialer: no fake relay success ---

    @Test
    fun `NotProvisionedRelayIngressDialer always fails closed with EXECUTION_NOT_IMPLEMENTED - never a fabricated success`() = runTest {
        val outcome = NotProvisionedRelayIngressDialer.dial(plan())
        assertTrue(outcome is RelayAttemptOutcome.Failure)
        val failure = outcome as RelayAttemptOutcome.Failure
        assertEquals(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED, failure.category)
        assertFalse(failure.isHealthy)
    }

    @Test
    fun `ingress and exit transports remain independently pinned when the plan is built`() {
        val p = plan(ingressTransport = TransportKind.XRAY_REALITY, exitTransport = TransportKind.TLS_TCP)
        assertEquals(TransportKind.XRAY_REALITY, p.ingressBinding.kind)
        assertEquals(TransportKind.TLS_TCP, p.exitBinding.kind)
        assertTrue(p.ingressTransport != p.exitTransport)
    }
}
