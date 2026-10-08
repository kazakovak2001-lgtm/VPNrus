package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PathSurvivabilityTest {
    @Test fun `S1 different endpoint IDs sharing domains have low independence`() {
        val result = assess(direct("a", domains("same")), direct("b", domains("same")))
        assertEquals(StructuralDiversity.LOW, result.structuralDiversity)
        assertTrue(SurvivabilityReason.SHARED_NETWORK_DOMAIN in result.reasons)
    }

    @Test fun `S2 different operator and network with shared control plane is partial`() {
        val result = assess(direct("a", domains("a", control = "shared")), direct("b", domains("b", control = "shared")))
        assertEquals(StructuralDiversity.PARTIAL, result.structuralDiversity)
        assertTrue(SurvivabilityReason.SHARED_CONTROL_PLANE_DOMAIN in result.reasons)
    }

    @Test fun `S3 fully distinct direct paths have strong structural diversity`() {
        assertEquals(StructuralDiversity.STRONG, assess(direct("a", domains("a")), direct("b", domains("b"))).structuralDiversity)
    }

    @Test fun `S4 shared CDN is visible correlation`() {
        val result = assess(relay("a", "cdn-one"), relay("b", "cdn-one"))
        assertTrue(SurvivabilityReason.SHARED_CDN_DOMAIN in result.reasons)
        assertEquals(1, result.failureDomainConcentration.uniqueKnownCdns)
    }

    @Test fun `S5 incomplete metadata remains unknown and adds no diversity`() {
        val result = assess(direct("a", domains("a")), direct("b", domains("b").copy(network = null)))
        assertEquals(StructuralDiversity.UNKNOWN, result.structuralDiversity)
        assertEquals(1, result.failureDomainConcentration.pathsWithUnknownDomains)
    }

    @Test fun `S6 diverse but unreachable preserves structure and reduces usable capacity`() {
        val result = assess(direct("a", domains("a")), direct("b", domains("b"), ReachabilityState.UNREACHABLE))
        assertEquals(StructuralDiversity.STRONG, result.structuralDiversity)
        assertEquals(1, result.currentReachability.usableNow)
    }

    @Test fun `S7 correlated healthy paths retain high current availability`() {
        val result = assess(direct("a", domains("same")), direct("b", domains("same")))
        assertEquals(StructuralDiversity.LOW, result.structuralDiversity)
        assertEquals(2, result.currentReachability.reachable)
    }

    @Test fun `S8 history changes reliability without changing structural diversity`() {
        val a = direct("a", domains("a")); val b = direct("b", domains("b"))
        val result = SurvivabilityAssessor.assess(listOf(
            SurvivabilityCandidate(a, history(1, 12, false, 5)), SurvivabilityCandidate(b, history(20, 1, true, 0))))
        assertEquals(StructuralDiversity.STRONG, result.structuralDiversity)
        assertEquals(HistoricalReliability.POOR, result.historicalReliability.classification)
    }

    @Test fun `S9 no history is unknown rather than failure`() {
        val result = assess(direct("a", domains("a")))
        assertEquals(HistoricalReliability.UNKNOWN, result.historicalReliability.classification)
        assertEquals(0, result.historicalReliability.observations)
    }

    @Test fun `S10 substantial stable history has higher confidence than one success`() {
        val path = direct("a", domains("a"))
        val small = SurvivabilityAssessor.assess(listOf(SurvivabilityCandidate(path, history(1, 0, true, 0))))
        val large = SurvivabilityAssessor.assess(listOf(SurvivabilityCandidate(path, history(100, 0, true, 0))))
        assertTrue(large.confidence.ordinal > small.confidence.ordinal)
    }

    @Test fun `S11 caller-selected network fingerprint history remains isolated`() {
        val path = direct("a", domains("a"))
        val networkA = SurvivabilityAssessor.assess(listOf(SurvivabilityCandidate(path, history(20, 0, true, 0))))
        val networkB = SurvivabilityAssessor.assess(listOf(SurvivabilityCandidate(path, history(0, 5, false, 5))))
        assertNotEquals(networkA.historicalReliability.classification, networkB.historicalReliability.classification)
    }

    @Test fun `S12 N minus one exposes operator network and control plane concentration`() {
        val result = assess(direct("a", domains("a", control = "shared")), direct("b", domains("b", control = "shared")))
        assertEquals(1, n1(result, FailureDomainDimension.OPERATOR).minimumRemainingUsablePaths)
        assertEquals(1, n1(result, FailureDomainDimension.NETWORK).minimumRemainingUsablePaths)
        assertEquals(0, n1(result, FailureDomainDimension.CONTROL_PLANE).minimumRemainingUsablePaths)
    }

    @Test fun `unknown failure domain has no fabricated N minus one value`() {
        val result = assess(direct("a", domains("a").copy(network = null)))
        assertNull(n1(result, FailureDomainDimension.NETWORK).minimumRemainingUsablePaths)
        assertEquals(1, n1(result, FailureDomainDimension.NETWORK).unknownPathCount)
    }

    @Test fun `empty and single candidate sets are explicit`() {
        val empty = SurvivabilityAssessor.assess(emptyList())
        assertEquals(OverallSurvivability.INSUFFICIENT_EVIDENCE, empty.overallAssessment)
        val single = assess(direct("a", domains("a")))
        assertTrue(SurvivabilityReason.SINGLE_CANDIDATE in single.reasons)
    }

    @Test fun `reason ordering and assessment are deterministic`() {
        val input = listOf(SurvivabilityCandidate(direct("a", domains("same"))), SurvivabilityCandidate(direct("b", domains("same"), ReachabilityState.UNREACHABLE)))
        val first = SurvivabilityAssessor.assess(input); val second = SurvivabilityAssessor.assess(input.reversed())
        assertEquals(first.copy(), second)
        assertEquals(first.reasons.sortedBy { it.ordinal }, first.reasons)
    }

    @Test fun `confidence is bounded enum and stable history reaches high confidence`() {
        val result = SurvivabilityAssessor.assess(listOf(
            SurvivabilityCandidate(direct("a", domains("a")), history(50, 1, true, 0)),
            SurvivabilityCandidate(direct("b", domains("b")), history(40, 2, true, 0))))
        assertEquals(AssessmentConfidence.HIGH, result.confidence)
        assertEquals(HistoricalReliability.STABLE, result.historicalReliability.classification)
    }

    private fun n1(a: PathSurvivabilityAssessment, d: FailureDomainDimension) = a.nMinusOne.single { it.dimension == d }
    private fun assess(vararg paths: PathCandidate) = SurvivabilityAssessor.assess(paths.map(::SurvivabilityCandidate))
    private fun history(success: Int, failure: Int, lastSuccess: Boolean, streak: Int) = PathHistoryEntry(success, failure, 100, lastSuccess, streak)
    private fun domains(prefix: String, control: String = "control-$prefix", cdn: String? = null) = InfrastructureFailureDomains(
        FailureDomainId("operator-$prefix"), FailureDomainId("network-$prefix"), FailureDomainId("region-$prefix"), cdn?.let(::FailureDomainId), FailureDomainId(control))

    private fun direct(id: String, d: InfrastructureFailureDomains, state: ReachabilityState = ReachabilityState.REACHABLE): PathCandidate.Direct {
        val endpoint = EndpointDescriptor(EndpointId(id), setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), "display", "display", transports = listOf(
            EndpointTransportBinding(TransportKind.XRAY_REALITY, "test.invalid", 443).withFailureDomains(d)))
        return requireNotNull(PathCandidateBuilder.buildDirect(endpoint, TransportKind.XRAY_REALITY, reach(endpoint.id, TransportKind.XRAY_REALITY, state)))
    }

    private fun relay(id: String, cdn: String): PathCandidate.Relayed {
        val exitId = EndpointId("exit-$id")
        val ingress = EndpointDescriptor(EndpointId("ingress-$id"), setOf(EndpointRole.INGRESS), "display", "display", transports = listOf(
            EndpointTransportBinding(TransportKind.XRAY_XHTTP, "test.invalid", 443).withIngressKind(IngressKind.CDN_FRONTED)
                .withFailureDomains(domains("ingress", cdn = cdn))), relayTo = exitId)
        val exit = EndpointDescriptor(exitId, setOf(EndpointRole.EXIT), "display", "display", transports = listOf(
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "test.invalid", 51820).withFailureDomains(domains("exit"))))
        return requireNotNull(PathCandidateBuilder.buildRelayed(ingress, exit, TransportKind.XRAY_XHTTP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.XRAY_XHTTP), reach(exit.id, TransportKind.AMNEZIA_WG)))
    }

    private fun reach(id: EndpointId, kind: TransportKind, state: ReachabilityState = ReachabilityState.REACHABLE) = EndpointReachability(
        id, kind, state, evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, 0, state == ReachabilityState.REACHABLE, true, RestrictionClass.UNKNOWN))
}
