package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportMaturity

/**
 * B8N - THE ONE place a transport's [TransportCapabilities] and
 * [TransportHealth] (both real, evidence-based typed models - see their
 * own docs) become a single deterministic score, matching architecture
 * principle 6's "capability/health scoring, not hardcoded if/else"
 * requirement. Pure, no I/O.
 *
 * Deliberately NOT consumed by SmartConnectDecisionEngine yet - same
 * "real evidence, truthfully surfaced, not yet decision-driving" boundary
 * already established for RestrictionClassifier/TransportHealth/
 * DiverseReachabilityEvaluator in this codebase. Wiring this into actual
 * transport SELECTION is a deliberate future step, not this one.
 */
object TransportScorer {

    /**
     * A NOT_IMPLEMENTED transport always scores lowest, regardless of
     * [health] - there is nothing real to prefer. Otherwise, [health]'s
     * CURRENT state dominates (it reflects what actually just happened,
     * the freshest evidence), with [capabilities]'s maturity only breaking
     * ties between two transports at the same health state - never the
     * other way around, since a merely-declared maturity level is a much
     * weaker signal than a real, recent connection outcome.
     */
    fun score(kind: TransportKind, capabilities: TransportCapabilities, health: TransportHealth): Int {
        if (capabilities.maturity == TransportMaturity.NOT_IMPLEMENTED) return Int.MIN_VALUE
        return healthComponent(health.state) * 10 + maturityComponent(capabilities.maturity)
    }

    /**
     * Kinds ranked BEST first (highest score first); ties broken by
     * [SmartConnectDecisionEngine.PREFERRED_ORDER] - the SAME list the
     * real decision authority uses, never a second, independently
     * maintained order that could silently disagree with it. A kind absent
     * from that list (should never happen - it enumerates every
     * [TransportKind]) sorts last among ties, never first, so an
     * unrecognized kind can't accidentally win a tie by omission.
     */
    fun rank(entries: Map<TransportKind, Pair<TransportCapabilities, TransportHealth>>): List<TransportKind> =
        entries.entries
            .sortedWith(
                compareByDescending<Map.Entry<TransportKind, Pair<TransportCapabilities, TransportHealth>>> {
                    score(it.key, it.value.first, it.value.second)
                }.thenBy {
                    SmartConnectDecisionEngine.PREFERRED_ORDER.indexOf(it.key).let { index -> if (index < 0) Int.MAX_VALUE else index }
                },
            )
            .map { it.key }

    private fun healthComponent(state: TransportHealthState): Int = when (state) {
        TransportHealthState.HEALTHY -> 3
        TransportHealthState.UNKNOWN -> 2
        TransportHealthState.DEGRADED -> 1
        TransportHealthState.UNREACHABLE -> 0
        TransportHealthState.NOT_IMPLEMENTED -> -1
    }

    private fun maturityComponent(maturity: TransportMaturity): Int = when (maturity) {
        TransportMaturity.STABLE -> 1
        TransportMaturity.EXPERIMENTAL -> 0
        TransportMaturity.NOT_IMPLEMENTED -> -1
    }
}
