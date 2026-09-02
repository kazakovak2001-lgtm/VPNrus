package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    // B23 (PR #37 review fix) - declares TWO transports so tests can exercise
    // an exit/upstream transport genuinely different from the ingress's own
    // client-facing transport (never assumed to match it).
    private val exit = EndpointDescriptor(
        EndpointId("exit1"), setOf(EndpointRole.EXIT), "us", "acme2",
        transports = listOf(
            EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.3", 51820),
            EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.4", 443),
        ),
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
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
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
            ingress, unrelatedExit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(unrelatedExit.id, TransportKind.AMNEZIA_WG),
        )
        assertNull(candidate)
    }

    @Test
    fun `buildRelayed rejects when ingress does not support the requested ingress transport`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.AMNEZIA_WG, TransportKind.AMNEZIA_WG, // ingress only declares TLS_TCP
            reach(ingress.id, TransportKind.AMNEZIA_WG),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )
        assertNull(candidate)
    }

    @Test
    fun `buildRelayed rejects when exit does not support the requested exit transport`() {
        val exitTlsOnly = exit.copy(transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.4", 443)))
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exitTlsOnly, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG, // exit only declares TLS_TCP
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(exitTlsOnly.id, TransportKind.AMNEZIA_WG),
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

    // --- B23: independent per-hop transports (PR #37 review fix) ---

    @Test
    fun `ingressTransport != exitTransport is representable - the ingress and exit hops never assume a shared transport`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        assertEquals(TransportKind.TLS_TCP, candidate.transport)
        assertEquals(TransportKind.AMNEZIA_WG, candidate.exitTransport)
        assertTrue(candidate.transport != candidate.exitTransport)
    }

    @Test
    fun `candidate identity changes when the ingress transport changes but the exit transport stays fixed`() {
        // Give the ingress a second transport so both can actually be built.
        val ingressTwoTransports = ingress.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.2", 443),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.2", 8443),
            ),
        )
        val viaTls = PathCandidateBuilder.buildRelayed(
            ingressTwoTransports, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingressTwoTransports.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        val viaReality = PathCandidateBuilder.buildRelayed(
            ingressTwoTransports, exit, TransportKind.XRAY_REALITY, TransportKind.AMNEZIA_WG,
            reach(ingressTwoTransports.id, TransportKind.XRAY_REALITY), reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        assertTrue(viaTls.id != viaReality.id)
        assertTrue(viaTls.historyPathId != viaReality.historyPathId)
    }

    @Test
    fun `candidate identity changes when the exit transport changes but the ingress transport stays fixed`() {
        val viaAwgExit = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        val viaTlsExit = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.TLS_TCP,
            reach(ingress.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.TLS_TCP),
        )!!
        assertTrue(viaAwgExit.id != viaTlsExit.id)
        assertTrue(viaAwgExit.historyPathId != viaTlsExit.historyPathId)
    }

    @Test
    fun `history keys never collide across a same-endpoints-different-transport-pair matrix`() {
        val ingressTwoTransports = ingress.copy(
            transports = listOf(
                EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.2", 443),
                EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.2", 8443),
            ),
        )
        val pairs = listOf(
            TransportKind.TLS_TCP to TransportKind.AMNEZIA_WG,
            TransportKind.TLS_TCP to TransportKind.TLS_TCP,
            TransportKind.XRAY_REALITY to TransportKind.AMNEZIA_WG,
            TransportKind.XRAY_REALITY to TransportKind.TLS_TCP,
        )
        val historyPathIds = pairs.map { (ingressKind, exitKind) ->
            PathCandidateBuilder.buildRelayed(
                ingressTwoTransports, exit, ingressKind, exitKind,
                reach(ingressTwoTransports.id, ingressKind), reach(exit.id, exitKind),
            )!!.historyPathId
        }
        assertEquals(historyPathIds.size, historyPathIds.toSet().size)
    }

    @Test
    fun `exact ingress and exit bindings remain pinned on the built candidate`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        assertEquals("203.0.113.2", candidate.ingress.binding.host)
        assertEquals(443, candidate.ingress.binding.port)
        assertEquals(TransportKind.TLS_TCP, candidate.ingress.binding.kind)
        assertEquals("203.0.113.3", candidate.exit.binding.host)
        assertEquals(51820, candidate.exit.binding.port)
        assertEquals(TransportKind.AMNEZIA_WG, candidate.exit.binding.kind)
    }

    // --- B23: historyPathId / pinning ---

    @Test
    fun `Direct historyPathId is exactly the gateway endpoint id - unchanged from pre-B23 PathHistoryStore keys`() {
        val candidate = PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG))!!
        assertEquals("gw", candidate.historyPathId)
    }

    @Test
    fun `legacy Direct candidate id and binding pinning are unaffected by the Relayed independent-transport change`() {
        val a = PathCandidateBuilder.buildDirect(gateway, TransportKind.AMNEZIA_WG, reach(gateway.id, TransportKind.AMNEZIA_WG))!!
        assertEquals("direct:AMNEZIA_WG:gw", a.id)
        assertEquals("gw", a.historyPathId)
        assertEquals("203.0.113.1", a.gateway.binding.host)
        assertEquals(51820, a.gateway.binding.port)
    }

    @Test
    fun `Relayed historyPathId is a composite ingress-then-exit id, distinct from either hop's own Direct id`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        assertEquals("in1:TLS_TCP->exit1:AMNEZIA_WG", candidate.historyPathId)
        assertTrue(candidate.historyPathId != ingress.id.value)
        assertTrue(candidate.historyPathId != exit.id.value)
    }

    @Test
    fun `two relays sharing the same ingress but different exits never share a historyPathId`() {
        val exit2 = exit.copy(id = EndpointId("exit2"))
        val ingressToExit2 = ingress.copy(relayTo = exit2.id)
        val a = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        val b = PathCandidateBuilder.buildRelayed(
            ingressToExit2, exit2, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP), reach(exit2.id, TransportKind.AMNEZIA_WG),
        )!!
        assertTrue(a.historyPathId != b.historyPathId)
    }

    /**
     * B23 - task requirement H10: a Relayed candidate's own pinned identity
     * (the exact endpoint snapshot each hop was built from) cannot mutate
     * mid-attempt just because a caller later resolves a DIFFERENT
     * descriptor for the same endpoint id (e.g. a manifest refresh mid-way
     * through one connection attempt) - same B16 pinning discipline already
     * proven for Direct/GatewayAttemptCandidate.
     */
    @Test
    fun `a built Relayed candidate keeps its own pinned endpoint snapshot even after a caller resolves a rotated descriptor for the same id`() {
        val candidate = PathCandidateBuilder.buildRelayed(
            ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
            reach(ingress.id, TransportKind.TLS_TCP),
            reach(exit.id, TransportKind.AMNEZIA_WG),
        )!!
        val rotatedIngress = ingress.copy(transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.99", 8443)))

        assertEquals("203.0.113.2", candidate.ingress.endpoint.bindingFor(TransportKind.TLS_TCP)!!.host)
        assertEquals("203.0.113.99", rotatedIngress.bindingFor(TransportKind.TLS_TCP)!!.host)
        assertEquals(
            candidate.id,
            PathCandidateBuilder.buildRelayed(
                ingress, exit, TransportKind.TLS_TCP, TransportKind.AMNEZIA_WG,
                reach(ingress.id, TransportKind.TLS_TCP), reach(exit.id, TransportKind.AMNEZIA_WG),
            )!!.id,
        )
    }
}
