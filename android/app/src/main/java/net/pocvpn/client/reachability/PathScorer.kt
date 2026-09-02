package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.smartconnect.SmartConnectDecisionEngine
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportMaturity
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus

/**
 * B11/B19 - deterministic path scoring, the SINGLE decision authority for
 * Auto gateway+transport ranking (see [net.pocvpn.client.smartconnect
 * .AutoGatewaySelector], its one production caller - never a second/parallel
 * scorer).
 *
 * Scoring uses ORDER-OF-MAGNITUDE tiers rather than a single flat weighted
 * sum, so that a higher-priority factor can NEVER be outweighed by a
 * lower-priority one, by construction rather than by careful tuning:
 *
 *   score = reachabilityRank * 1_000_000   (dominant - endpoint reachability)
 *         + transportHealthRank * 10_000   (transport-wide health)
 *         + historyRank * 1_000            (this network's own local memory)
 *         + restrictionRank * 700          (B28 - restriction-evidence path-type preference)
 *         + maturityRank * 200             (declared capability maturity)
 *         - latencyPenalty (capped at 50)  (small - measured latency only)
 *         - recentFailurePenalty (capped at 80, summed across hops)
 *         - cooldownPenalty (capped at 60) (B19 - bounded, time-decaying, this-network failure streak)
 *         + diversityBonus (capped at 5)   (smallest - provider/ASN spread)
 *
 * Each tier's weight is strictly larger than the sum of EVERY weight below
 * it, verified per tier (not just eyeballed) against each factor's actual
 * min/max RANGE, not just its cap:
 *   maturity     (range width (1-(-1))*200=400) >  diversity+latency+failure+cooldown max (5+50+80+60=195)
 *   restriction  (range width (1-(-1))*700=1400) > maturity range+lower (400+195=595)
 *   history      (range width (2-(-1))*1000=3000) > restriction range+lower (1400+595=1995)
 *   health       (range width (3-(-1))*10000=40000) > history range+lower (3000+1995=4995)
 *   reachability (1_000_000 per rank) > health range+lower (40000+4995=44995)
 * MATURITY_TIER=200 is deliberately NOT 100: at 100 it would be possible for
 * MAX_LATENCY_PENALTY+MAX_FAILURE_PENALTY+MAX_COOLDOWN_PENALTY+MAX_DIVERSITY_BONUS
 * (195) to outweigh a single maturity-rank step (100), letting an
 * EXPERIMENTAL transport with zero penalties outrank a STABLE one carrying
 * penalties - exactly the kind of lower-priority-outweighs-higher-priority
 * bug this tiering exists to make structurally impossible. RESTRICTION_TIER=700
 * is deliberately sandwiched strictly ABOVE maturity but BELOW history: a
 * device's own real local success/failure memory on THIS network is
 * stronger, more specific evidence than a coarse restriction classification,
 * but a restriction preference should still outrank mere declared transport
 * maturity. See PathScorerTest's boundary tests for the worst-case proof at
 * each tier.
 *
 * B28 - restriction-evidence tier: [RestrictionClass.POSSIBLE_HARD_WHITELIST]
 * is the ONLY restriction class that contributes a nonzero restrictionRank
 * (+1 for [PathCandidate.Relayed], -1 for [PathCandidate.Direct]) - every
 * other class (including UNKNOWN/NO_RESTRICTION_OBSERVED/
 * POSSIBLE_UDP_OR_AWG_FILTERING) contributes exactly 0, so normal healthy
 * direct behavior is completely unaffected outside a suspected hard
 * whitelist (requirement 1). POSSIBLE_UDP_OR_AWG_FILTERING deliberately
 * gets NO dedicated branch here: it is itself derived from a real
 * awgHandshakeFresh==false ConnectionOutcome, which ALREADY penalizes the
 * AMNEZIA_WG transport kind via the existing HEALTH_TIER
 * (TransportHealthCalculator) - a second, protocol-specific branch would be
 * exactly the redundant nested-if/else the task asked NOT to add
 * (requirement 2). This is scoring only - eligibility ([isEligible]) is
 * completely untouched by restriction evidence, so a relay candidate that
 * fails eligibility can never be promoted merely because whitelist evidence
 * looks bad (requirement 4), and both [net.pocvpn.client.smartconnect
 * .IngressKind] values participate identically - the bonus depends only on
 * candidate TYPE (Direct vs Relayed), never on which ingress kind, so
 * DIRECT_IP and CDN_FRONTED candidates are ranked among themselves purely by
 * their own reachability/health/history (requirement 3).
 *
 * B19 - typed reason tokens (see [Reason]) are appended to [PathScoreResult
 * .reasons] alongside the existing free-text summaries (never replacing
 * them - every pre-B19 reader of a specific string is unaffected) so a
 * diagnostics UI/test can match on a stable token rather than parsing prose.
 *
 * B19-3 - ELIGIBILITY (a separate concern from ranking, checked first, see
 * [isEligible]'s own docs for the exact precedence): fresh endpoint-specific
 * [ReachabilityState.UNREACHABLE] and [net.pocvpn.client.transport
 * .TransportHealthState.NOT_IMPLEMENTED] make a candidate ineligible
 * (`PathScoreResult.eligible = false`, never merely low-scored) - an
 * ineligible candidate never becomes an executable
 * [net.pocvpn.client.smartconnect.GatewayAttemptCandidate] (see
 * [net.pocvpn.client.smartconnect.AutoGatewaySelector], which already only
 * ever promotes `eligible == true` results - this file remains the ONE
 * place that decision is made). `DEGRADED`/`UNKNOWN` remain eligible,
 * penalized only by [score]'s own tiering below.
 */
object PathScorer {

    /** B19 - stable, typed diagnostic tokens (task's own required vocabulary) - never a substitute for the actual score, only for human/UI-facing "why". */
    enum class Reason {
        ENDPOINT_REACHABLE, ENDPOINT_DEGRADED, ENDPOINT_UNREACHABLE, ENDPOINT_UNKNOWN,
        TRANSPORT_HEALTHY, TRANSPORT_DEGRADED, TRANSPORT_UNREACHABLE, TRANSPORT_UNKNOWN, TRANSPORT_NOT_IMPLEMENTED,
        RECENT_SUCCESS_THIS_NETWORK, RECENT_FAILURE_THIS_NETWORK,
        FAILURE_COOLDOWN,
        STATIC_TRANSPORT_PREFERENCE,
        DIVERSITY_BONUS,
        /** B28 - POSSIBLE_HARD_WHITELIST evidence favored this RELAYED candidate over a direct path. */
        RESTRICTION_FAVORS_RELAY,
        /** B28 - POSSIBLE_HARD_WHITELIST evidence penalized this DIRECT candidate relative to relayed alternatives. */
        RESTRICTION_PENALIZES_DIRECT,
    }

    data class PathScoreResult(
        val candidate: PathCandidate,
        val eligible: Boolean,
        val score: Long,
        val reasons: List<String>,
    )

    /**
     * B19-3 - the ONE place candidate eligibility is decided (this file's own
     * single-authority contract - never a second filtering layer in
     * `AutoGatewaySelector`/`MainViewModel`/`TransportOrchestrator`). Checked
     * before any scoring. Explicit precedence, first match wins:
     *
     *  1. Transport not `AVAILABLE` in the registry, or [transportHealth] is
     *     [TransportHealthState.NOT_IMPLEMENTED] -> ineligible (nothing can
     *     execute this kind at all).
     *  2. Fresh endpoint-specific [ReachabilityState.UNREACHABLE] (the worst
     *     hop's own `reachability.state` - already the FRESH, endpoint-
     *     specific-aware value `ReachabilityEngine.assess` produces; stale
     *     evidence already decays to [ReachabilityState.UNKNOWN] THERE, so
     *     this is deliberately the ONLY freshness check - never a second,
     *     duplicate implementation here) -> ineligible, REGARDLESS of
     *     transport-wide health - the strongest, most specific signal wins.
     *  3. [TransportHealthState.UNREACHABLE] (transport-wide) -> ineligible
     *     UNLESS some hop's own reachability is confirmed
     *     [ReachabilityState.REACHABLE] - fresh, stronger, endpoint-specific
     *     evidence is never overridden by a coarser transport-wide claim
     *     (task's own "do not let transport-wide UNREACHABLE override
     *     stronger fresh endpoint-specific REACHABLE evidence").
     *  4. Everything else (`DEGRADED`/`UNKNOWN` on either signal) remains
     *     eligible, penalized by [score]'s own tiering, never excluded.
     */
    fun isEligible(candidate: PathCandidate, registry: TransportRegistry, transportHealth: TransportHealth): Boolean =
        ineligibilityReason(candidate, registry, transportHealth) == null

    /** Returns the typed [Reason] this candidate is ineligible for, or null when it IS eligible - see [isEligible]'s own docs for the exact precedence. */
    private fun ineligibilityReason(candidate: PathCandidate, registry: TransportRegistry, transportHealth: TransportHealth): Reason? {
        val descriptor = registry.descriptorFor(candidate.transport)
        if (descriptor == null || descriptor.status != TransportStatus.AVAILABLE) return Reason.TRANSPORT_NOT_IMPLEMENTED
        if (transportHealth.state == TransportHealthState.NOT_IMPLEMENTED) return Reason.TRANSPORT_NOT_IMPLEMENTED

        val worstHopReachability = candidate.hops.minByOrNull { reachabilityRank(it.reachability.state) }?.reachability?.state
            ?: ReachabilityState.UNKNOWN
        if (worstHopReachability == ReachabilityState.UNREACHABLE) return Reason.ENDPOINT_UNREACHABLE

        if (transportHealth.state == TransportHealthState.UNREACHABLE) {
            val anyHopConfirmedReachable = candidate.hops.any { it.reachability.state == ReachabilityState.REACHABLE }
            if (!anyHopConfirmedReachable) return Reason.TRANSPORT_UNREACHABLE
        }
        return null
    }

    /**
     * B19 - [nowEpochMillis] and [history] together drive the bounded,
     * time-decaying failure-cooldown penalty (see [FAILURE_COOLDOWN_WINDOW_MILLIS]).
     * [nowEpochMillis] defaults to [Long.MAX_VALUE] so every pre-B19 caller
     * (which never set [PathHistoryEntry.consecutiveFailures] either, itself
     * defaulted to 0) computes a cooldown penalty of exactly 0, byte-for-byte
     * unaffected.
     */
    fun score(
        candidate: PathCandidate,
        registry: TransportRegistry,
        capabilities: TransportCapabilities,
        transportHealth: TransportHealth,
        history: PathHistoryEntry?,
        diverseProviderOrAsnSeenElsewhere: Boolean,
        nowEpochMillis: Long = Long.MAX_VALUE,
    ): PathScoreResult {
        ineligibilityReason(candidate, registry, transportHealth)?.let { reason ->
            return PathScoreResult(
                candidate,
                eligible = false,
                score = Long.MIN_VALUE,
                reasons = listOf("transport ${candidate.transport} is not eligible: $reason", reason.name),
            )
        }

        val reasons = mutableListOf<String>()

        val worstHopReachability = candidate.hops.minByOrNull { reachabilityRank(it.reachability.state) }?.reachability?.state
            ?: ReachabilityState.UNKNOWN
        val reachabilityScore = reachabilityRank(worstHopReachability).toLong() * REACHABILITY_TIER
        reasons += "reachability=$worstHopReachability"
        reasons += reachabilityReasonToken(worstHopReachability).name

        val healthScore = healthRank(transportHealth.state).toLong() * HEALTH_TIER
        reasons += "transportHealth=${transportHealth.state}"
        reasons += healthReasonToken(transportHealth.state).name

        val historyScore = historyRank(history).toLong() * HISTORY_TIER
        if (history != null) {
            reasons += "history=${history.successCount}s/${history.failureCount}f"
            reasons += (if (history.lastOutcomeSuccess) Reason.RECENT_SUCCESS_THIS_NETWORK else Reason.RECENT_FAILURE_THIS_NETWORK).name
        }

        // B28 - restriction-evidence path-type preference (see class docs'
        // own tier-algebra proof and RESTRICTION_TIER's placement between
        // HISTORY_TIER and MATURITY_TIER). Read directly off this
        // candidate's own hop evidence - every hop of a given candidate
        // carries the SAME RestrictionClass (MainViewModel computes it once
        // per read and threads it into every ReachabilityEngine.assess call
        // for that read), so the first hop's value is authoritative for the
        // whole candidate.
        val restrictionClass = candidate.hops.firstOrNull()?.reachability?.evidence?.restrictionClass
        val restrictionRank = restrictionRank(candidate, restrictionClass)
        val restrictionScore = restrictionRank.toLong() * RESTRICTION_TIER
        if (restrictionRank > 0) {
            reasons += "restriction=$restrictionClass favors relay"
            reasons += Reason.RESTRICTION_FAVORS_RELAY.name
        } else if (restrictionRank < 0) {
            reasons += "restriction=$restrictionClass penalizes direct"
            reasons += Reason.RESTRICTION_PENALIZES_DIRECT.name
        }

        val maturityScore = maturityRank(capabilities.maturity).toLong() * MATURITY_TIER

        val latencyPenalty = candidate.hops.mapNotNull { it.reachability.latencyMillis }.maxOrNull()
            ?.let { (it / 20).coerceIn(0, MAX_LATENCY_PENALTY) } ?: 0L
        if (latencyPenalty > 0) reasons += "latencyPenalty=$latencyPenalty"

        // Summed, not maxOf: a Relayed candidate where BOTH hops recently
        // failed their own probe is worse than one where only one did - see
        // the class doc's own "capped at 80" (2 hops x 40 each), which a
        // max-of-hops reduction could never actually reach.
        val recentFailures: Long = candidate.hops.sumOf { hop -> if (hop.reachability.evidence.endpointSpecificReachable == false) 1L else 0L }
        val failurePenalty = (recentFailures * 40L).coerceAtMost(MAX_FAILURE_PENALTY)
        if (failurePenalty > 0) reasons += "recentFailurePenalty=$failurePenalty"

        // B19 - a BOUNDED, TIME-DECAYING per-path cooldown, never a
        // permanent blacklist: only the RECENT streak (consecutiveFailures,
        // reset by any success - see PathHistoryEntry's own docs) within
        // [FAILURE_COOLDOWN_WINDOW_MILLIS] of [nowEpochMillis] contributes
        // anything at all - once that window elapses the penalty is exactly
        // 0 again, "naturally expires" by construction, not by a second
        // cleanup mechanism.
        val cooldownPenalty = history?.let { h ->
            if (h.consecutiveFailures <= 0) return@let 0L
            val age = nowEpochMillis - h.lastOutcomeEpochMillis
            if (age < 0 || age > FAILURE_COOLDOWN_WINDOW_MILLIS) return@let 0L
            (h.consecutiveFailures.toLong() * COOLDOWN_STEP_PENALTY).coerceAtMost(MAX_COOLDOWN_PENALTY)
        } ?: 0L
        if (cooldownPenalty > 0) {
            reasons += "cooldownPenalty=$cooldownPenalty"
            reasons += Reason.FAILURE_COOLDOWN.name
        }

        val diversityBonus = if (diverseProviderOrAsnSeenElsewhere) MAX_DIVERSITY_BONUS else 0L
        if (diversityBonus > 0) {
            reasons += "diversityBonus=$diversityBonus"
            reasons += Reason.DIVERSITY_BONUS.name
        }

        val total = reachabilityScore + healthScore + historyScore + restrictionScore + maturityScore - latencyPenalty - failurePenalty - cooldownPenalty + diversityBonus
        return PathScoreResult(candidate, eligible = true, score = total, reasons = reasons)
    }

    private fun reachabilityReasonToken(state: ReachabilityState): Reason = when (state) {
        ReachabilityState.REACHABLE -> Reason.ENDPOINT_REACHABLE
        ReachabilityState.DEGRADED -> Reason.ENDPOINT_DEGRADED
        ReachabilityState.UNREACHABLE -> Reason.ENDPOINT_UNREACHABLE
        ReachabilityState.UNKNOWN -> Reason.ENDPOINT_UNKNOWN
    }

    private fun healthReasonToken(state: TransportHealthState): Reason = when (state) {
        TransportHealthState.HEALTHY -> Reason.TRANSPORT_HEALTHY
        TransportHealthState.DEGRADED -> Reason.TRANSPORT_DEGRADED
        TransportHealthState.UNREACHABLE -> Reason.TRANSPORT_UNREACHABLE
        TransportHealthState.UNKNOWN -> Reason.TRANSPORT_UNKNOWN
        TransportHealthState.NOT_IMPLEMENTED -> Reason.TRANSPORT_NOT_IMPLEMENTED
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

    /**
     * B28 - the ONLY place restriction evidence turns into a scoring
     * preference (requirement 7's single-decision-authority contract).
     * Nonzero ONLY for [RestrictionClass.POSSIBLE_HARD_WHITELIST] - every
     * other class (NORMAL/UNKNOWN included) is 0, so ordinary healthy
     * direct behavior is never disturbed (requirement 1). +1 for
     * [PathCandidate.Relayed] (bonus - a relay MAY route around a
     * suspected fixed allowlist), -1 for [PathCandidate.Direct] (penalty -
     * a direct path to a foreign EXIT is exactly what a hard whitelist
     * would block) - symmetric so the tier-algebra proof in the class doc
     * above covers both directions with the same range. Depends only on
     * candidate TYPE, never on [net.pocvpn.client.smartconnect.IngressKind]
     * - DIRECT_IP and CDN_FRONTED relayed candidates receive the identical
     * +1, so neither ingress kind is ever globally preferred over the
     * other by this tier (requirement 3); their relative order among
     * themselves is still decided entirely by the higher REACHABILITY_TIER/
     * HEALTH_TIER/HISTORY_TIER above.
     */
    private fun restrictionRank(candidate: PathCandidate, restrictionClass: RestrictionClass?): Int {
        if (restrictionClass != RestrictionClass.POSSIBLE_HARD_WHITELIST) return 0
        return when (candidate) {
            is PathCandidate.Relayed -> 1
            is PathCandidate.Direct -> -1
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
    /** B28 - see class doc's own tier-algebra proof for why 700 sits safely between HISTORY_TIER and MATURITY_TIER. */
    private const val RESTRICTION_TIER = 700L
    private const val MATURITY_TIER = 200L
    private const val MAX_LATENCY_PENALTY = 50L
    private const val MAX_FAILURE_PENALTY = 80L
    private const val MAX_DIVERSITY_BONUS = 5L

    /** B19 - how long a recent failure streak on this network keeps contributing a cooldown penalty before naturally expiring. */
    const val FAILURE_COOLDOWN_WINDOW_MILLIS: Long = 5 * 60 * 1000L
    private const val COOLDOWN_STEP_PENALTY = 20L
    private const val MAX_COOLDOWN_PENALTY = 60L
}
