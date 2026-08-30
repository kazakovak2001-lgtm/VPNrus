package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportDescriptor
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportMaturity
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PathScorerTest {

    private fun endpoint(id: String, kind: TransportKind) = EndpointDescriptor(
        EndpointId(id), setOf(EndpointRole.GATEWAY), "eu", "acme",
        transports = listOf(EndpointTransportBinding(kind, "203.0.113.1", 51820)),
    )

    private fun reach(id: EndpointId, kind: TransportKind, state: ReachabilityState, latencyMillis: Long? = null) = EndpointReachability(
        id, kind, state, latencyMillis = latencyMillis,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, null, true, RestrictionClass.UNKNOWN),
    )

    private fun candidate(id: String, kind: TransportKind, state: ReachabilityState, latencyMillis: Long? = null): PathCandidate.Direct {
        val e = endpoint(id, kind)
        return PathCandidateBuilder.buildDirect(e, kind, reach(e.id, kind, state, latencyMillis))!!
    }

    private fun registryWith(kind: TransportKind, status: TransportStatus): TransportRegistry = TransportRegistry.build(
        listOf(
            TransportDescriptor(
                kind = kind,
                status = status,
                capabilities = if (status == TransportStatus.NOT_IMPLEMENTED) TransportCapabilities.notImplemented() else TransportCapabilities.amneziaWg(),
                factory = if (status == TransportStatus.AVAILABLE) ({ FakeVpnTransport() }) else null,
            ),
        ),
    )

    @Test
    fun `unreachable never beats reachable, no matter the latency penalty`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val reachableSlow = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = 5000L)
        val unreachableFast = candidate("gw2", TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE, latencyMillis = 1L)

        val scoreReachable = PathScorer.score(reachableSlow, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        val scoreUnreachable = PathScorer.score(unreachableFast, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)

        assertTrue(scoreReachable.score > scoreUnreachable.score)
    }

    @Test
    fun `a NOT_IMPLEMENTED transport is ineligible and never wins`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.NOT_IMPLEMENTED)
        val candidate = candidate("gw1", TransportKind.TLS_TCP, ReachabilityState.REACHABLE)
        val result = PathScorer.score(candidate, registry, TransportCapabilities.notImplemented(), TransportHealth(), null, false)
        assertFalse(result.eligible)
        assertEquals(Long.MIN_VALUE, result.score)
    }

    @Test
    fun `healthy transport beats degraded transport at the same reachability state`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val healthy = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        val degraded = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.DEGRADED), null, false)
        assertTrue(healthy.score > degraded.score)
    }

    @Test
    fun `recent failure history penalizes the score but never flips reachability dominance`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val noHistory = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        val badHistory = PathHistoryEntry(successCount = 1, failureCount = 9, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = false)
        val withHistory = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), badHistory, false)
        assertTrue(noHistory.score > withHistory.score)

        val unreachable = candidate("gw2", TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE)
        val goodHistory = PathHistoryEntry(successCount = 9, failureCount = 0, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = true)
        val unreachableWithGoodHistory = PathScorer.score(unreachable, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), goodHistory, false)
        assertTrue(withHistory.score > unreachableWithGoodHistory.score)
    }

    @Test
    fun `ranking ties are broken deterministically`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val a = candidate("gw-a", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val b = candidate("gw-b", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val results1 = PathScorer.rank(listOf(a, b).map { PathScorer.score(it, registry, TransportCapabilities.amneziaWg(), health, null, false) })
        val results2 = PathScorer.rank(listOf(b, a).map { PathScorer.score(it, registry, TransportCapabilities.amneziaWg(), health, null, false) })
        assertEquals(results1.map { it.candidate.id }, results2.map { it.candidate.id })
    }

    @Test
    fun `diversity bonus never overrides hard reachability evidence`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val unreachableDiverse = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE)
        val reachableNotDiverse = candidate("gw2", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val diverse = PathScorer.score(unreachableDiverse, registry, TransportCapabilities.amneziaWg(), health, null, diverseProviderOrAsnSeenElsewhere = true)
        val notDiverse = PathScorer.score(reachableNotDiverse, registry, TransportCapabilities.amneziaWg(), health, null, diverseProviderOrAsnSeenElsewhere = false)
        assertTrue(notDiverse.score > diverse.score)
    }

    @Test
    fun `maturity only breaks ties at the same health and reachability state`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val stable = PathScorer.score(c, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE), health, null, false)
        val experimental = PathScorer.score(c, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.EXPERIMENTAL), health, null, false)
        assertTrue(stable.score > experimental.score)
    }
}
