package net.pocvpn.client.smartconnect

/**
 * B8M - THE ONE place several diverse, independent reachability probe
 * results become a single "is a broad/diverse set of unrelated real
 * destinations reachable" signal. Pure, no I/O, no probing itself - see
 * RestrictionMonitor's own docs for where the real probes actually run.
 * Deliberately majority-based, never "any one succeeded" (a single
 * reachable destination proves almost nothing about the network as a
 * whole) and never "all must succeed" (a single unrelated outage
 * shouldn't flip this) - see evaluate()'s own docs.
 */
object DiverseReachabilityEvaluator {

    /**
     * `null` (unknown, never claim from insufficient evidence) when no
     * probe ran. Otherwise true iff a STRICT MAJORITY of [results]
     * reported reachable - ties (impossible with an odd probe count, but
     * kept explicit for any future even count) count as NOT reachable, the
     * conservative direction for a signal RestrictionClassifier may use to
     * suspect narrow allowlisting.
     */
    fun evaluate(results: List<Boolean>): Boolean? {
        if (results.isEmpty()) return null
        val reachableCount = results.count { it }
        return reachableCount * 2 > results.size
    }
}
