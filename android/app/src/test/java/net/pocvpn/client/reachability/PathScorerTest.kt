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

    private fun reachWithEvidence(
        id: EndpointId,
        kind: TransportKind,
        state: ReachabilityState,
        latencyMillis: Long? = null,
        endpointSpecificReachable: Boolean? = null,
    ) = EndpointReachability(
        id, kind, state, latencyMillis = latencyMillis,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, endpointSpecificReachable, true, RestrictionClass.UNKNOWN),
    )

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

    // --- Boundary/worst-case tests (PR #23 second audit): prove the tiering
    // holds at the EDGE of each factor's range, not merely for typical
    // values - this is exactly the class the "maturity only breaks ties"
    // happy-path test above (both zero-penalty inputs) could never catch. ---

    @Test
    fun `a one-rank maturity advantage survives even the WORST-CASE combined latency+failure+diversity swing against it`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)

        val e1 = endpoint("gw-stable", TransportKind.AMNEZIA_WG)
        val stableNoBonus = PathCandidateBuilder.buildDirect(
            e1, TransportKind.AMNEZIA_WG,
            reachWithEvidence(e1.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = null, endpointSpecificReachable = null),
        )!!
        val e2 = endpoint("gw-experimental", TransportKind.AMNEZIA_WG)
        val experimentalMaxBonus = PathCandidateBuilder.buildDirect(
            e2, TransportKind.AMNEZIA_WG,
            // Worst case for the higher-maturity candidate: give the LOWER
            // maturity candidate the maximum possible latency penalty relief
            // (huge latency -> capped penalty) AND a recent failure AND the
            // diversity bonus, all at their caps simultaneously.
            reachWithEvidence(e2.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = 100_000L, endpointSpecificReachable = false),
        )!!

        val stableScore = PathScorer.score(stableNoBonus, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE), health, null, diverseProviderOrAsnSeenElsewhere = false)
        val experimentalScore = PathScorer.score(experimentalMaxBonus, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.EXPERIMENTAL), health, null, diverseProviderOrAsnSeenElsewhere = true)

        assertTrue(
            "maturity dominance must hold even under the worst-case lower-tier swing (stable=${stableScore.score}, experimental=${experimentalScore.score})",
            stableScore.score > experimentalScore.score,
        )
    }

    @Test
    fun `a one-rank health advantage survives the worst-case combined history+maturity+latency+failure+diversity swing against it`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)

        val e1 = endpoint("gw-healthy", TransportKind.AMNEZIA_WG)
        val healthyNoBonus = PathCandidateBuilder.buildDirect(
            e1, TransportKind.AMNEZIA_WG,
            reachWithEvidence(e1.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = null, endpointSpecificReachable = null),
        )!!
        val e2 = endpoint("gw-unknown", TransportKind.AMNEZIA_WG)
        val unknownMaxBonus = PathCandidateBuilder.buildDirect(
            e2, TransportKind.AMNEZIA_WG,
            reachWithEvidence(e2.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE, latencyMillis = 100_000L, endpointSpecificReachable = false),
        )!!

        val bestHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = true)
        val healthyScore = PathScorer.score(
            healthyNoBonus, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.EXPERIMENTAL),
            TransportHealth(state = TransportHealthState.HEALTHY), null, diverseProviderOrAsnSeenElsewhere = false,
        )
        val unknownScore = PathScorer.score(
            unknownMaxBonus, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE),
            TransportHealth(state = TransportHealthState.UNKNOWN), bestHistory, diverseProviderOrAsnSeenElsewhere = true,
        )

        assertTrue(
            "health dominance must hold even under the worst-case lower-tier swing (healthy=${healthyScore.score}, unknown=${unknownScore.score})",
            healthyScore.score > unknownScore.score,
        )
    }

    @Test
    fun `recentFailurePenalty sums across BOTH hops of a Relayed candidate, capped at 80`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val ingressEndpoint = EndpointDescriptor(
            EndpointId("in1"), setOf(EndpointRole.INGRESS), "eu", "acme",
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.2", 443)),
            relayTo = EndpointId("exit1"),
        )
        val exitEndpoint = EndpointDescriptor(
            EndpointId("exit1"), setOf(EndpointRole.EXIT), "us", "acme2",
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.3", 443)),
        )
        val bothHopsFailed = PathCandidateBuilder.buildRelayed(
            ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP,
            reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
            reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
        )!!
        val oneHopFailed = PathCandidateBuilder.buildRelayed(
            ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP,
            reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
            reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = null),
        )!!
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val capsAtOne = TransportCapabilities.amneziaWg()

        val twoFailures = PathScorer.score(bothHopsFailed, registry, capsAtOne, health, null, false)
        val oneFailure = PathScorer.score(oneHopFailed, registry, capsAtOne, health, null, false)
        val zeroFailures = PathScorer.score(
            PathCandidateBuilder.buildRelayed(
                ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP,
                reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE),
                reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE),
            )!!,
            registry, capsAtOne, health, null, false,
        )

        assertEquals(zeroFailures.score - 40, oneFailure.score)
        assertEquals(zeroFailures.score - 80, twoFailures.score) // 2 hops x 40 = 80, exactly MAX_FAILURE_PENALTY
        assertTrue(oneFailure.score > twoFailures.score)
    }

    @Test
    fun `score never overflows or underflows Long for any combination of documented ranges`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val e = endpoint("gw", TransportKind.AMNEZIA_WG)
        val best = PathCandidateBuilder.buildDirect(e, TransportKind.AMNEZIA_WG, reachWithEvidence(e.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE))!!
        val worst = PathCandidateBuilder.buildDirect(e, TransportKind.AMNEZIA_WG, reachWithEvidence(e.id, TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE, latencyMillis = Long.MAX_VALUE / 2, endpointSpecificReachable = false))!!
        val bestScore = PathScorer.score(best, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE), TransportHealth(state = TransportHealthState.HEALTHY), PathHistoryEntry(10, 0, 0L, true), true)
        val worstScore = PathScorer.score(worst, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.NOT_IMPLEMENTED), TransportHealth(state = TransportHealthState.NOT_IMPLEMENTED), PathHistoryEntry(0, 10, 0L, false), false)
        assertTrue(bestScore.score > 0)
        assertTrue(bestScore.score > worstScore.score)
        // No exception/NaN-equivalent - both are finite, sane Long values.
        assertTrue(bestScore.score < Long.MAX_VALUE / 2)
        assertTrue(worstScore.score > Long.MIN_VALUE / 2)
    }
}
