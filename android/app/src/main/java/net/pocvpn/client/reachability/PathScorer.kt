package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.SmartConnectDecisionEngine
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportMaturity
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus

/**
 * B11 - deterministic path scoring. OBSERVATIONAL ONLY in this slice - see
 * the task's own Smart Connect boundary: nothing here is consulted by
 * SmartConnectDecisionEngine/AwgXrayFailoverPolicy yet.
 *
 * Scoring uses ORDER-OF-MAGNITUDE tiers rather than a single flat weighted
 * sum, so that a higher-priority factor can NEVER be outweighed by a
 * lower-priority one, by construction rather than by careful tuning:
 *
 *   score = reachabilityRank * 1_000_000   (dominant - endpoint reachability)
 *         + transportHealthRank * 10_000   (transport-wide health)
 *         + historyRank * 1_000            (this network's own local memory)
 *         + maturityRank * 100             (declared capability maturity)
 *         - latencyPenalty (capped at 50)  (small - measured latency only)
 *         - recentFailurePenalty (capped at 80)
 *         + diversityBonus (capped at 5)   (smallest - provider/ASN spread)
 *
 * Each tier's weight is strictly larger than the sum of every weight below
 * it (1_000_000 > 10_000+1_000+100+80+5, and so on down the list), so e.g.
 * "unreachable never beats reachable due to latency" and "diversity never
 * overrides hard reachability evidence" hold for ANY latency/diversity
 * value within their capped range, not merely for typical ones.
 */
object PathScorer {

    data class PathScoreResult(
        val candidate: PathCandidate,
        val eligible: Boolean,
        val score: Long,
        val reasons: List<String>,
    )

    /** invalid/unsupported/NOT_IMPLEMENTED transports are ineligible - checked before any scoring. */
    fun isEligible(candidate: PathCandidate, registry: TransportRegistry): Boolean {
        val descriptor = registry.descriptorFor(candidate.transport) ?: return false
        return descriptor.status == TransportStatus.AVAILABLE
    }

    fun score(
        candidate: PathCandidate,
        registry: TransportRegistry,
        capabilities: TransportCapabilities,
        transportHealth: TransportHealth,
        history: PathHistoryEntry?,
        diverseProviderOrAsnSeenElsewhere: Boolean,
    ): PathScoreResult {
        if (!isEligible(candidate, registry)) {
            return PathScoreResult(candidate, eligible = false, score = Long.MIN_VALUE, reasons = listOf("transport ${candidate.transport} is not AVAILABLE"))
        }

        val reasons = mutableListOf<String>()

        val worstHopReachability = candidate.hops.minByOrNull { reachabilityRank(it.reachability.state) }?.reachability?.state
            ?: ReachabilityState.UNKNOWN
        val reachabilityScore = reachabilityRank(worstHopReachability).toLong() * REACHABILITY_TIER
        reasons += "reachability=$worstHopReachability"

        val healthScore = healthRank(transportHealth.state).toLong() * HEALTH_TIER
        reasons += "transportHealth=${transportHealth.state}"

        val historyScore = historyRank(history).toLong() * HISTORY_TIER
        if (history != null) reasons += "history=${history.successCount}s/${history.failureCount}f"

        val maturityScore = maturityRank(capabilities.maturity).toLong() * MATURITY_TIER

        val latencyPenalty = candidate.hops.mapNotNull { it.reachability.latencyMillis }.maxOrNull()
            ?.let { (it / 20).coerceIn(0, MAX_LATENCY_PENALTY) } ?: 0L
        if (latencyPenalty > 0) reasons += "latencyPenalty=$latencyPenalty"

        val recentFailures = candidate.hops.maxOfOrNull { it.reachability.evidence.let { e -> if (e.endpointSpecificReachable == false) 1 else 0 } } ?: 0
        val failurePenalty = (recentFailures * 40L).coerceAtMost(MAX_FAILURE_PENALTY)
        if (failurePenalty > 0) reasons += "recentFailurePenalty=$failurePenalty"

        val diversityBonus = if (diverseProviderOrAsnSeenElsewhere) MAX_DIVERSITY_BONUS else 0L
        if (diversityBonus > 0) reasons += "diversityBonus=$diversityBonus"

        val total = reachabilityScore + healthScore + historyScore + maturityScore - latencyPenalty - failurePenalty + diversityBonus
        return PathScoreResult(candidate, eligible = true, score = total, reasons = reasons)
    }

    /** Best first; deterministic ties broken by SmartConnectDecisionEngine.PREFERRED_ORDER (same list the real decision authority uses), then by candidate.id lexicographically as a final, fully-deterministic tiebreak. */
    fun rank(results: List<PathScoreResult>): List<PathScoreResult> = results.sortedWith(
        compareByDescending<PathScoreResult> { it.score }
            .thenBy { SmartConnectDecisionEngine.PREFERRED_ORDER.indexOf(it.candidate.transport).let { i -> if (i < 0) Int.MAX_VALUE else i } }
            .thenBy { it.candidate.id },
    )

    private fun reachabilityRank(state: ReachabilityState): Int = when (state) {
        ReachabilityState.REACHABLE -> 3
        ReachabilityState.UNKNOWN -> 2
        ReachabilityState.DEGRADED -> 1
        ReachabilityState.UNREACHABLE -> 0
    }

    private fun healthRank(state: TransportHealthState): Int = when (state) {
        TransportHealthState.HEALTHY -> 3
        TransportHealthState.UNKNOWN -> 2
        TransportHealthState.DEGRADED -> 1
        TransportHealthState.UNREACHABLE -> 0
        TransportHealthState.NOT_IMPLEMENTED -> -1
    }

    private fun historyRank(history: PathHistoryEntry?): Int {
        if (history == null) return 0
        if (history.successCount == 0 && history.failureCount == 0) return 0
        val successRatio = history.successCount.toDouble() / (history.successCount + history.failureCount)
        return when {
            successRatio >= 0.75 -> 2
            successRatio >= 0.25 -> 1
            else -> -1
        }
    }

    private fun maturityRank(maturity: TransportMaturity): Int = when (maturity) {
        TransportMaturity.STABLE -> 1
        TransportMaturity.EXPERIMENTAL -> 0
        TransportMaturity.NOT_IMPLEMENTED -> -1
    }

    private const val REACHABILITY_TIER = 1_000_000L
    private const val HEALTH_TIER = 10_000L
    private const val HISTORY_TIER = 1_000L
    private const val MATURITY_TIER = 100L
    private const val MAX_LATENCY_PENALTY = 50L
    private const val MAX_FAILURE_PENALTY = 80L
    private const val MAX_DIVERSITY_BONUS = 5L
}
