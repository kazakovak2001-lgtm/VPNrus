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
        restrictionClass: RestrictionClass = RestrictionClass.UNKNOWN,
    ) = EndpointReachability(
        id, kind, state, latencyMillis = latencyMillis,
        evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, endpointSpecificReachable, true, restrictionClass),
    )

    private fun directCandidate(id: String, kind: TransportKind, restrictionClass: RestrictionClass): PathCandidate.Direct {
        val e = endpoint(id, kind)
        return PathCandidateBuilder.buildDirect(e, kind, reachWithEvidence(e.id, kind, ReachabilityState.REACHABLE, restrictionClass = restrictionClass))!!
    }

    private fun relayedCandidate(
        ingressId: String,
        exitId: String,
        kind: TransportKind,
        restrictionClass: RestrictionClass,
        ingressKind: IngressKind = IngressKind.DIRECT_IP,
    ): PathCandidate.Relayed {
        val ingressEndpoint = EndpointDescriptor(
            EndpointId(ingressId), setOf(EndpointRole.INGRESS), "eu", "acme",
            transports = listOf(EndpointTransportBinding(kind, "203.0.113.10", 443).withIngressKind(ingressKind)),
            relayTo = EndpointId(exitId),
        )
        val exitEndpoint = EndpointDescriptor(
            EndpointId(exitId), setOf(EndpointRole.EXIT), "us", "acme2",
            transports = listOf(EndpointTransportBinding(kind, "203.0.113.11", 443)),
        )
        return PathCandidateBuilder.buildRelayed(
            ingressEndpoint, exitEndpoint, kind, kind,
            reachWithEvidence(ingressEndpoint.id, kind, ReachabilityState.REACHABLE, restrictionClass = restrictionClass),
            reachWithEvidence(exitEndpoint.id, kind, ReachabilityState.REACHABLE, restrictionClass = restrictionClass),
        )!!
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
            ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP, TransportKind.TLS_TCP,
            reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
            reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
        )!!
        val oneHopFailed = PathCandidateBuilder.buildRelayed(
            ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP, TransportKind.TLS_TCP,
            reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = false),
            reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, endpointSpecificReachable = null),
        )!!
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val capsAtOne = TransportCapabilities.amneziaWg()

        val twoFailures = PathScorer.score(bothHopsFailed, registry, capsAtOne, health, null, false)
        val oneFailure = PathScorer.score(oneHopFailed, registry, capsAtOne, health, null, false)
        val zeroFailures = PathScorer.score(
            PathCandidateBuilder.buildRelayed(
                ingressEndpoint, exitEndpoint, TransportKind.TLS_TCP, TransportKind.TLS_TCP,
                reachWithEvidence(ingressEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE),
                reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE),
            )!!,
            registry, capsAtOne, health, null, false,
        )

        assertEquals(zeroFailures.score - 40, oneFailure.score)
        assertEquals(zeroFailures.score - 80, twoFailures.score) // 2 hops x 40 = 80, exactly MAX_FAILURE_PENALTY
        assertTrue(oneFailure.score > twoFailures.score)
    }

    // --- B19: bounded, time-decaying failure cooldown ---

    @Test
    fun `a recent failure streak within the cooldown window produces a bounded penalty`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        // Identical successCount/failureCount/lastOutcomeSuccess (so the
        // historyRank tier is IDENTICAL for both) - only consecutiveFailures
        // (the cooldown trigger) differs, isolating exactly what the
        // cooldown penalty itself contributes.
        val base = PathHistoryEntry(successCount = 5, failureCount = 3, lastOutcomeEpochMillis = 999_000L, lastOutcomeSuccess = false)
        val noStreak = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, base, false, nowEpochMillis = 1_000_000L)
        val withStreak = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, base.copy(consecutiveFailures = 2), false, nowEpochMillis = 1_000_000L)

        assertTrue(noStreak.score > withStreak.score)
        assertTrue(withStreak.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
        assertFalse(noStreak.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
    }

    @Test
    fun `the cooldown penalty is capped, not proportional to an unbounded streak`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val hugeStreak = PathHistoryEntry(successCount = 0, failureCount = 500, lastOutcomeEpochMillis = 999_000L, lastOutcomeSuccess = false, consecutiveFailures = 500)
        val moderateStreak = PathHistoryEntry(successCount = 0, failureCount = 5, lastOutcomeEpochMillis = 999_000L, lastOutcomeSuccess = false, consecutiveFailures = 5)

        val hugeScore = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, hugeStreak, false, nowEpochMillis = 1_000_000L)
        val moderateScore = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, moderateStreak, false, nowEpochMillis = 1_000_000L)

        // Both streaks are large enough to hit the same cap - the penalty must be identical, not scaled further.
        assertEquals(moderateScore.score, hugeScore.score)
    }

    @Test
    fun `the cooldown penalty naturally expires once the failure streak is older than the cooldown window`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val streak = PathHistoryEntry(
            successCount = 0, failureCount = 4, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = false, consecutiveFailures = 4,
        )
        // SAME history entry, only "now" moves from inside to just outside the cooldown window.
        val withinWindow = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, streak, false, nowEpochMillis = PathScorer.FAILURE_COOLDOWN_WINDOW_MILLIS)
        val afterWindow = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, streak, false, nowEpochMillis = PathScorer.FAILURE_COOLDOWN_WINDOW_MILLIS + 1L)

        assertTrue(withinWindow.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
        assertFalse(afterWindow.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
        assertTrue("cooldown must expire, raising the score back up (within=${withinWindow.score}, after=${afterWindow.score})", afterWindow.score > withinWindow.score)
    }

    @Test
    fun `a successful reconnect clears the cooldown penalty - consecutiveFailures resets to 0`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val clearedByRecentSuccess = PathHistoryEntry(
            successCount = 6, failureCount = 3, lastOutcomeEpochMillis = 999_999L, lastOutcomeSuccess = true, consecutiveFailures = 0,
        )
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, clearedByRecentSuccess, false, nowEpochMillis = 1_000_000L)
        val noHistory = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, null, false, nowEpochMillis = 1_000_000L)

        assertFalse(result.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
        // The historyRank tier still differs (real history vs none) - only the cooldown penalty itself is asserted absent above.
        assertTrue(result.score >= noHistory.score)
    }

    @Test
    fun `pre-B19 callers - no nowEpochMillis, default PathHistoryEntry - see zero cooldown penalty regardless of consecutiveFailures default`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val legacyHistory = PathHistoryEntry(successCount = 1, failureCount = 9, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = false)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), health, legacyHistory, false)
        assertFalse(result.reasons.contains(PathScorer.Reason.FAILURE_COOLDOWN.name))
    }

    // --- B19: typed reason tokens ---

    @Test
    fun `reasons carry stable typed tokens alongside the existing free-text summaries`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        assertTrue(result.reasons.contains(PathScorer.Reason.ENDPOINT_REACHABLE.name))
        assertTrue(result.reasons.contains(PathScorer.Reason.TRANSPORT_HEALTHY.name))
    }

    @Test
    fun `score never overflows or underflows Long for any combination of documented ranges`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val e = endpoint("gw", TransportKind.AMNEZIA_WG)
        val best = PathCandidateBuilder.buildDirect(e, TransportKind.AMNEZIA_WG, reachWithEvidence(e.id, TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE))!!
        // B19-3 - the worst ELIGIBLE combination: DEGRADED (not UNREACHABLE -
        // that is now ineligible outright, see the dedicated eligibility
        // tests below) reachability/health, every penalty at its cap, worst
        // maturity, no diversity bonus.
        val worstEligible = PathCandidateBuilder.buildDirect(e, TransportKind.AMNEZIA_WG, reachWithEvidence(e.id, TransportKind.AMNEZIA_WG, ReachabilityState.DEGRADED, latencyMillis = Long.MAX_VALUE / 2, endpointSpecificReachable = false))!!
        val bestScore = PathScorer.score(best, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE), TransportHealth(state = TransportHealthState.HEALTHY), PathHistoryEntry(10, 0, 0L, true), true)
        val worstScore = PathScorer.score(worstEligible, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.NOT_IMPLEMENTED), TransportHealth(state = TransportHealthState.DEGRADED), PathHistoryEntry(0, 10, 0L, false), false)
        assertTrue(worstScore.eligible)
        assertTrue(bestScore.score > 0)
        assertTrue(bestScore.score > worstScore.score)
        // No exception/NaN-equivalent - both are finite, sane Long values.
        assertTrue(bestScore.score < Long.MAX_VALUE / 2)
        assertTrue(worstScore.score > Long.MIN_VALUE / 2)
    }

    @Test
    fun `a genuinely ineligible candidate (fresh UNREACHABLE, NOT_IMPLEMENTED health+maturity) scores the exact MIN_VALUE sentinel, never an underflow`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val e = endpoint("gw", TransportKind.AMNEZIA_WG)
        val ineligible = PathCandidateBuilder.buildDirect(e, TransportKind.AMNEZIA_WG, reachWithEvidence(e.id, TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE, latencyMillis = Long.MAX_VALUE / 2, endpointSpecificReachable = false))!!
        val result = PathScorer.score(ineligible, registry, TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.NOT_IMPLEMENTED), TransportHealth(state = TransportHealthState.NOT_IMPLEMENTED), PathHistoryEntry(0, 10, 0L, false), false)
        assertFalse(result.eligible)
        assertEquals(Long.MIN_VALUE, result.score)
    }

    // --- B19-3: eligibility contract - fresh UNREACHABLE/NOT_IMPLEMENTED are ineligible, never merely low-scored ---

    @Test
    fun `fresh endpoint-specific UNREACHABLE makes the candidate ineligible regardless of transport health`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.UNREACHABLE)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        assertFalse(result.eligible)
        assertTrue(result.reasons.contains(PathScorer.Reason.ENDPOINT_UNREACHABLE.name))
    }

    @Test
    fun `endpoint REACHABLE plus transport-wide UNREACHABLE - fresh endpoint-specific evidence wins, candidate stays eligible`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.UNREACHABLE), null, false)
        assertTrue(result.eligible)
    }

    @Test
    fun `endpoint UNKNOWN plus transport-wide UNREACHABLE - no stronger evidence to override, ineligible`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.UNKNOWN)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.UNREACHABLE), null, false)
        assertFalse(result.eligible)
        assertTrue(result.reasons.contains(PathScorer.Reason.TRANSPORT_UNREACHABLE.name))
    }

    @Test
    fun `DEGRADED reachability remains eligible`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.DEGRADED)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        assertTrue(result.eligible)
    }

    @Test
    fun `UNKNOWN reachability with UNKNOWN transport health remains eligible`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.UNKNOWN)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.UNKNOWN), null, false)
        assertTrue(result.eligible)
    }

    @Test
    fun `NOT_IMPLEMENTED transport health makes the candidate ineligible even with REACHABLE endpoint evidence`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val result = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.NOT_IMPLEMENTED), null, false)
        assertFalse(result.eligible)
        assertTrue(result.reasons.contains(PathScorer.Reason.TRANSPORT_NOT_IMPLEMENTED.name))
    }

    @Test
    fun `stale-decayed UNREACHABLE evidence arrives as UNKNOWN from ReachabilityEngine and is eligible again - no second freshness check in PathScorer`() {
        // ReachabilityEngine.assess is what actually decays stale evidence to
        // UNKNOWN (see that object's own docs) - this proves PathScorer
        // trusts whatever state it is handed, never re-deriving staleness.
        val now = 10_000_000L
        val staleEvidence = ReachabilityEngine.assess(
            endpoint = EndpointDescriptor(EndpointId("gw1"), setOf(EndpointRole.GATEWAY), "eu", "acme", transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820))),
            transportKind = TransportKind.AMNEZIA_WG,
            networkUsable = true,
            transportHealth = TransportHealth(state = TransportHealthState.UNREACHABLE, lastProbeEpochMillis = 0L),
            endpointSpecificReachable = false,
            restrictionClass = RestrictionClass.UNKNOWN,
            nowEpochMillis = now,
            endpointSpecificOutcomeEpochMillis = 0L,
        )
        assertEquals(ReachabilityState.UNKNOWN, staleEvidence.state)

        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val candidate = PathCandidateBuilder.buildDirect(endpoint("gw1", TransportKind.AMNEZIA_WG), TransportKind.AMNEZIA_WG, staleEvidence)!!
        // A fresh transportHealth read now shows UNKNOWN too (the same stale-decay reasoning) - not the original UNREACHABLE.
        val result = PathScorer.score(candidate, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.UNKNOWN), null, false)
        assertTrue(result.eligible)
    }

    // --- B28: restriction-evidence path-type preference ---

    @Test
    fun `NORMAL (UNKNOWN) restriction evidence never forces relay over an equally-healthy direct candidate`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.UNKNOWN)
        val relayed = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.UNKNOWN)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val directScore = PathScorer.score(direct, registry, TransportCapabilities.amneziaWg(), health, null, false)
        val relayedScore = PathScorer.score(relayed, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertTrue(directScore.eligible && relayedScore.eligible)
        assertEquals(directScore.score, relayedScore.score)
        assertFalse(directScore.reasons.contains(PathScorer.Reason.RESTRICTION_PENALIZES_DIRECT.name))
        assertFalse(relayedScore.reasons.contains(PathScorer.Reason.RESTRICTION_FAVORS_RELAY.name))
    }

    @Test
    fun `NO_RESTRICTION_OBSERVED also never forces relay - only POSSIBLE_HARD_WHITELIST does`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.NO_RESTRICTION_OBSERVED)
        val relayed = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.NO_RESTRICTION_OBSERVED)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val directScore = PathScorer.score(direct, registry, TransportCapabilities.amneziaWg(), health, null, false)
        val relayedScore = PathScorer.score(relayed, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertEquals(directScore.score, relayedScore.score)
    }

    @Test
    fun `POSSIBLE_HARD_WHITELIST evidence makes an equally-reachable relay outrank direct`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val relayed = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val directScore = PathScorer.score(direct, registry, TransportCapabilities.amneziaWg(), health, null, false)
        val relayedScore = PathScorer.score(relayed, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertTrue(relayedScore.score > directScore.score)
        assertTrue(directScore.reasons.contains(PathScorer.Reason.RESTRICTION_PENALIZES_DIRECT.name))
        assertTrue(relayedScore.reasons.contains(PathScorer.Reason.RESTRICTION_FAVORS_RELAY.name))
    }

    @Test
    fun `both DIRECT_IP and CDN_FRONTED relayed candidates get the identical POSSIBLE_HARD_WHITELIST bonus - neither kind is globally preferred`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val directIpRelay = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST, ingressKind = IngressKind.DIRECT_IP)
        val cdnRelay = relayedCandidate("in2", "exit1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST, ingressKind = IngressKind.CDN_FRONTED)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val directIpScore = PathScorer.score(directIpRelay, registry, TransportCapabilities.amneziaWg(), health, null, false)
        val cdnScore = PathScorer.score(cdnRelay, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertEquals(directIpScore.score, cdnScore.score)
    }

    @Test
    fun `an unhealthy - unreachable relay is not selected just because POSSIBLE_HARD_WHITELIST is suspected - the bonus never overrides fresh UNREACHABLE ineligibility`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val e = EndpointDescriptor(
            EndpointId("in-bad"), setOf(EndpointRole.INGRESS), "eu", "acme",
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.20", 443).withIngressKind(IngressKind.DIRECT_IP)),
            relayTo = EndpointId("exit1"),
        )
        val exitEndpoint = EndpointDescriptor(
            EndpointId("exit1"), setOf(EndpointRole.EXIT), "us", "acme2",
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.21", 443)),
        )
        val unreachableRelay = PathCandidateBuilder.buildRelayed(
            e, exitEndpoint, TransportKind.TLS_TCP, TransportKind.TLS_TCP,
            reachWithEvidence(e.id, TransportKind.TLS_TCP, ReachabilityState.UNREACHABLE, restrictionClass = RestrictionClass.POSSIBLE_HARD_WHITELIST),
            reachWithEvidence(exitEndpoint.id, TransportKind.TLS_TCP, ReachabilityState.REACHABLE, restrictionClass = RestrictionClass.POSSIBLE_HARD_WHITELIST),
        )!!
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val relayedScore = PathScorer.score(unreachableRelay, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertFalse("a fresh-UNREACHABLE relay hop must stay ineligible regardless of restriction evidence", relayedScore.eligible)
        // The direct candidate, still eligible, ranks ahead - never fabricating a healthy relay to preserve connectivity.
        val directScore = PathScorer.score(direct, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertTrue(directScore.eligible)
        assertTrue(directScore.score > relayedScore.score)
    }

    @Test
    fun `POSSIBLE_UDP_OR_AWG_FILTERING carries no dedicated restriction-tier branch - AMNEZIA_WG is penalized only via the existing HEALTH_TIER`() {
        val registry = registryWith(TransportKind.AMNEZIA_WG, TransportStatus.AVAILABLE)
        val c = candidate("gw1", TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE)
        val healthyNoFiltering = PathScorer.score(c, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        val filteredAwg = EndpointReachability(
            EndpointId("gw1"), TransportKind.AMNEZIA_WG, ReachabilityState.REACHABLE,
            evidence = ReachabilityEvidenceSummary(TransportHealthState.HEALTHY, null, null, true, RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING),
        )
        val cFiltered = PathCandidateBuilder.buildDirect(endpoint("gw1", TransportKind.AMNEZIA_WG), TransportKind.AMNEZIA_WG, filteredAwg)!!
        val filteredScore = PathScorer.score(cFiltered, registry, TransportCapabilities.amneziaWg(), TransportHealth(state = TransportHealthState.HEALTHY), null, false)
        // Same (healthy) transport health -> POSSIBLE_UDP_OR_AWG_FILTERING alone contributes exactly 0 restriction score - the real penalty only shows up once TransportHealth itself reflects the failed handshake (a separate, already-existing HEALTH_TIER path, not exercised here).
        assertEquals(healthyNoFiltering.score, filteredScore.score)
        assertFalse(filteredScore.reasons.contains(PathScorer.Reason.RESTRICTION_FAVORS_RELAY.name))
        assertFalse(filteredScore.reasons.contains(PathScorer.Reason.RESTRICTION_PENALIZES_DIRECT.name))
    }

    @Test
    fun `restriction preference is strong enough to survive a worst-case combined maturity+latency+failure+diversity swing but never outweighs history`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val relayed = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        // Worst case for direct: give the RELAY zero bonuses (no maturity, no diversity) and the DIRECT candidate the maximum possible maturity+diversity swing.
        val directScore = PathScorer.score(
            direct, registry, TransportCapabilities.amneziaWg().copy(maturity = net.pocvpn.client.transport.TransportMaturity.STABLE),
            health, null, diverseProviderOrAsnSeenElsewhere = true,
        )
        val relayedScore = PathScorer.score(
            relayed, registry, TransportCapabilities.amneziaWg().copy(maturity = net.pocvpn.client.transport.TransportMaturity.NOT_IMPLEMENTED),
            health, null, diverseProviderOrAsnSeenElsewhere = false,
        )
        assertTrue(
            "restriction dominance over maturity/diversity must hold even under worst-case swing (direct=${directScore.score}, relayed=${relayedScore.score})",
            relayedScore.score > directScore.score,
        )
    }

    @Test
    fun `a real local history advantage on this network still outranks a mere POSSIBLE_HARD_WHITELIST-only relay preference`() {
        val registry = registryWith(TransportKind.TLS_TCP, TransportStatus.AVAILABLE)
        val direct = directCandidate("gw1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val relayed = relayedCandidate("in1", "exit1", TransportKind.TLS_TCP, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val bestHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 0L, lastOutcomeSuccess = true)
        val health = TransportHealth(state = TransportHealthState.HEALTHY)
        val directScoreWithHistory = PathScorer.score(direct, registry, TransportCapabilities.amneziaWg(), health, bestHistory, false)
        val relayedScoreNoHistory = PathScorer.score(relayed, registry, TransportCapabilities.amneziaWg(), health, null, false)
        assertTrue(directScoreWithHistory.score > relayedScoreNoHistory.score)
    }
}
