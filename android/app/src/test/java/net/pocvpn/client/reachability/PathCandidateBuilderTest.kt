package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PathCandidateBuilderTest {

    private fun reach(id: EndpointId, kind: TransportKind, state: ReachabilityState = ReachabilityState.REACHABLE) = EndpointReachability(
        id, kind, state,
        evidence = ReachabilityEvidenceSummary(net.pocvpn.client.transport.TransportHealthState.HEALTHY, null, true, true, RestrictionClass.UNKNOWN),
    )

    private val gateway = EndpointDescriptor(
        EndpointId("gw"), setOf(EndpointRole.GATEWAY, EndpointRole.EXIT), "eu", "acme",
        transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
    )

    private val ingress = EndpointDescriptor(
        EndpointId("in1"), setOf(EndpointRole.INGRESS), "eu", "acme",
        transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.2", 443)),
        relayTo = EndpointId("exit1"),
    )

    private val exit = EndpointDescriptor(
        EndpointId("exit1"), setOf(EndpointRole.EXIT), "us", "acme2",
        transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.3", 51820)),
    )

    @Test
    fun `buildDirect produces a single-hop candidate for a real GATEWAY endpoint`() {
        val candidate = PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG))
        assertNotNull(candidate)
        assertEquals(1, candidate!!.hops.size)
        assertEquals(EndpointRole.GATEWAY, candidate.hops.first().role)
    }

    @Test
    fun `buildDirect rejects a transport the gateway does not support`() {
        val candidate = PathCandidateBuilder.buildDirect(gateway, TransportKind.TLS_TCP, reach(gateway.id, TransportKind.TLS_TCP))
        assertNull(candidate)
    }

    @Test
    fun `buildDirect rejects an endpoint with no GATEWAY or EXIT role`() {
        val ingressOnly = ingress
        val candidate = PathCandidateBuilder.buildDirect(ingressOnly, TransportKind.TLS_TCP, reach(ingressOnly.id, TransportKind.TLS_TCP))
        assertNull(candidate)
    }

    @Test
    fun `buildRelayed produces an INGRESS then EXIT chain when the manifest names that relationship`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )
        assertNotNull(candidate)
        assertEquals(listOf(EndpointRole.INGRESS, EndpointRole.EXIT), candidate!!.hops.map { it.role })
        assertEquals(ingress.id, candidate.ingress.endpoint.id)
        assertEquals(exit.id, candidate.exit.endpoint.id)
    }

    @Test
    fun `buildRelayed rejects a chain the manifest does not actually declare (relayTo mismatch)`() {
        val unrelatedExit = exit.copy(id = EndpointId("not-the-real-exit"))
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, unrelatedExit, TransportKind.TLS_TCP,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(unrelatedExit.id, TransportKind.AMNEZIA_WG),
        )
        assertNull(candidate)
    }

    @Test
    fun `buildRelayed rejects when ingress does not support the requested transport`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.AMNEZIA_WG, // ingress only declares TLS_TCP
            reach(ingress.id, TransportKind.AMNEZIA_WG),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )
        assertNull(candidate)
    }

    @Test
    fun `construction is deterministic - same inputs produce equal candidates`() {
        val a = PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG))
        val b = PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG))
        assertEquals(a, b)
        assertEquals(a!!.id, b!!.id)
    }
}
