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
