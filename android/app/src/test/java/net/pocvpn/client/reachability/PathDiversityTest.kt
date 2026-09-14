package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PathDiversityTest {
    private fun domains(prefix: String, cdn: String? = null) = InfrastructureFailureDomains(
        FailureDomainId("op-$prefix"), FailureDomainId("net-$prefix"), FailureDomainId("region-$prefix"),
        cdn?.let(::FailureDomainId), FailureDomainId("control-$prefix"),
    )

    private fun reach(id: EndpointId) = EndpointReachability(id, TransportKind.XRAY_REALITY, ReachabilityState.REACHABLE,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, true, true, RestrictionClass.UNKNOWN))

    private fun direct(id: String, domains: InfrastructureFailureDomains?): PathCandidate.Direct {
        val endpoint = EndpointDescriptor(EndpointId(id), setOf(EndpointRole.GATEWAY), "display", "display",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "test.invalid", 443).let { binding -> domains?.let(binding::withFailureDomains) ?: binding }))
        return requireNotNull(PathCandidateBuilder.buildDirect(endpoint, TransportKind.XRAY_REALITY, reach(endpoint.id)))
    }

    @Test fun `only a candidate with a unique fully trusted domain receives the bounded preference`() {
        val a = direct("a", domains("one")); val b = direct("b", domains("one")); val c = direct("c", domains("two"))
        assertEquals(setOf(c.id), PathDiversity.independentlyDiverseCandidateIds(listOf(a, b, c)))
    }

    @Test fun `missing or malformed metadata never creates false independence`() {
        val unknown = direct("unknown", null)
        val malformed = direct("bad", InfrastructureFailureDomains(null, FailureDomainId("net-x"), FailureDomainId("region-x"), null, FailureDomainId("control-x")))
        assertTrue(PathDiversity.independentlyDiverseCandidateIds(listOf(unknown, malformed)).isEmpty())
        assertFalse(EndpointTransportBinding(TransportKind.XRAY_REALITY, "test.invalid", 443, mapOf("failureDomain.operator" to "bad space")).failureDomains().isCompleteForNonCdnPath)
    }

    @Test fun `same raw ID in different dimensions remains independent`() {
        val first = direct("first", InfrastructureFailureDomains(
            FailureDomainId("operator"), FailureDomainId("net-a"), FailureDomainId("region"), FailureDomainId("shared"), FailureDomainId("control")))
        val second = direct("second", InfrastructureFailureDomains(
            FailureDomainId("shared"), FailureDomainId("net-a"), FailureDomainId("region"), null, FailureDomainId("control")))
        assertEquals(setOf(first.id, second.id), PathDiversity.independentlyDiverseCandidateIds(listOf(first, second)))
    }

    @Test fun `same dimension ID correlates and does not create a diversity bonus`() {
        val first = direct("first", domains("same"))
        val second = direct("second", domains("same"))
        assertTrue(PathDiversity.independentlyDiverseCandidateIds(listOf(first, second)).isEmpty())
    }

    @Test fun `withFailureDomains clears stale nullable domains and preserves unrelated metadata`() {
        val binding = EndpointTransportBinding(
            TransportKind.XRAY_XHTTP,
            "test.invalid",
            443,
            mapOf(
                "ingressKind" to IngressKind.CDN_FRONTED.name,
                "sni" to "edge.invalid",
                "failureDomain.operator" to "old-op",
                "failureDomain.network" to "old-net",
                "failureDomain.region" to "old-region",
                "failureDomain.cdn" to "old-cdn",
                "failureDomain.controlPlane" to "old-control",
            ),
        )
        val updated = binding.withFailureDomains(
            InfrastructureFailureDomains(FailureDomainId("new-op"), null, null, null, FailureDomainId("new-control")))
        assertEquals(IngressKind.CDN_FRONTED.name, updated.metadata["ingressKind"])
        assertEquals("edge.invalid", updated.metadata["sni"])
        assertEquals("new-op", updated.metadata["failureDomain.operator"])
        assertEquals("new-control", updated.metadata["failureDomain.controlPlane"])
        assertTrue(updated.metadata.keys.none { it == "failureDomain.network" || it == "failureDomain.region" || it == "failureDomain.cdn" })
        assertTrue(updated.failureDomains().network == null)
    }

    @Test fun `CDN relayed path requires a CDN domain and preserves shared exit correlation`() {
        val ingress = EndpointDescriptor(EndpointId("ingress"), setOf(EndpointRole.INGRESS), "display", "display",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_XHTTP, "test.invalid", 443).withIngressKind(IngressKind.CDN_FRONTED).withFailureDomains(domains("ingress", "cdn-one"))), relayTo = EndpointId("exit"))
        val exit = EndpointDescriptor(EndpointId("exit"), setOf(EndpointRole.EXIT), "display", "display",
            transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "test.invalid", 51820).withFailureDomains(domains("exit"))))
        val candidate = requireNotNull(PathCandidateBuilder.buildRelayed(ingress, exit, TransportKind.XRAY_XHTTP, TransportKind.AMNEZIA_WG,
            EndpointReachability(ingress.id, TransportKind.XRAY_XHTTP, ReachabilityState.REACHABLE, evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, true, true, RestrictionClass.UNKNOWN)), EndpointReachability(exit.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, true, true, RestrictionClass.UNKNOWN))))
        assertTrue(PathDiversity.independentlyDiverseCandidateIds(listOf(candidate)).isEmpty())
    }
}
