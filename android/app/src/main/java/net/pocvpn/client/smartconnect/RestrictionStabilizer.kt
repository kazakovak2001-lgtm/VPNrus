package net.pocvpn.client.smartconnect

/**
 * B28 review fix (blocker 2) - a small, pure, deterministic MINIMUM-RESIDENCE
 * stabilizer sitting ON TOP of [RestrictionClassifier.classify]'s own
 * staleness handling (see that function's own docs), never replacing it:
 * `classify()` already decides what the CURRENT raw evidence means and
 * expires evidence older than its own `staleAfterMillis`; this object
 * decides whether a raw classification that DIFFERS from the currently
 * "established" (decision-driving) class has persisted long enough to be
 * trusted as a genuine change, rather than a single transient probe result.
 *
 * Without this, [PathScorer]'s restriction-evidence tier (B28) would
 * re-rank DIRECT vs RELAYED on every single fresh `classify()` call, so a
 * sequence like HARD_WHITELIST -> UNKNOWN -> HARD_WHITELIST (two different
 * probe results a few seconds apart) could flip the decision twice in a
 * row - exactly the oscillation this object exists to prevent.
 *
 * Chosen mechanism: option (b) from the task's own two options - a short
 * MINIMUM-RESIDENCE hold window, not "N consistent observations" (that
 * would require buffering an unbounded observation history; a residence
 * window needs only the single most-recent pending observation and its own
 * timestamp, staying genuinely bounded/O(1) state).
 *
 * [RestrictionClass.NO_NETWORK] and [RestrictionClass.CAPTIVE_PORTAL] are
 * EXEMPT from hysteresis entirely (task requirement: "should not be hidden
 * behind long hysteresis") - both take effect the instant they are
 * observed, and leaving either takes effect just as instantly, since a
 * genuinely no-network/captive-portal condition (or its genuine recovery)
 * is itself the strongest, most literal signal this codebase has and must
 * never be artificially delayed.
 */
object RestrictionStabilizer {

    /**
     * Deliberately short - "do not require long delays" (task's own words).
     * Chosen to comfortably exceed the time between two REAL, distinct
     * [RestrictionMonitor] probe triggers during active reconnect churn
     * (each triggered only by a genuine transport-state/network-type
     * transition, never a timer - see that class's own docs) while staying
     * far below anything a user would perceive as "stuck."
     */
    const val DEFAULT_MIN_RESIDENCE_MILLIS: Long = 90 * 1000L

    /**
     * [establishedClass] is the current decision-driving value (what
     * [PathScorer]/[RestrictionClassifier]'s consumers should actually use).
     * [pendingClass]/[pendingSinceEpochMillis] track a DIFFERING raw
     * observation that has not yet resided long enough to be promoted -
     * null/null when there is nothing pending (the most recent raw
     * observation already equals [establishedClass]).
     */
    data class State(
        val establishedClass: RestrictionClass,
        val establishedAtEpochMillis: Long,
        val pendingClass: RestrictionClass? = null,
        val pendingSinceEpochMillis: Long? = null,
    )

    /**
     * The very first observation any session ever makes is trusted
     * immediately - there is no prior established value to protect, so
     * hysteresis has nothing meaningful to do yet. Only SUBSEQUENT changes
     * away from an already-established value are subject to the residence
     * window below.
     */
    fun initial(nowEpochMillis: Long, firstObservedClass: RestrictionClass): State =
        State(establishedClass = firstObservedClass, establishedAtEpochMillis = nowEpochMillis)

    private fun isImmediate(restrictionClass: RestrictionClass): Boolean =
        restrictionClass == RestrictionClass.NO_NETWORK || restrictionClass == RestrictionClass.CAPTIVE_PORTAL

    /**
     * Advances [state] with one new raw classification. Pure - no I/O, no
     * mutation of [state] itself (returns a new [State]), fully determined
     * by its arguments alone.
     */
    fun advance(
        state: State,
        rawClass: RestrictionClass,
        nowEpochMillis: Long,
        minResidenceMillis: Long = DEFAULT_MIN_RESIDENCE_MILLIS,
    ): State {
        // NO_NETWORK/CAPTIVE_PORTAL bypass hysteresis entirely, both
        // entering (raw is one of them) and leaving (the established value
        // WAS one of them, and something else is now observed) - neither
        // direction is ever held behind the residence window.
        if (isImmediate(rawClass) || isImmediate(state.establishedClass)) {
            return State(establishedClass = rawClass, establishedAtEpochMillis = nowEpochMillis)
        }

        if (rawClass == state.establishedClass) {
            // Confirms the already-established value - any earlier pending
            // flip away from it is no longer relevant, clear it.
            return if (state.pendingClass == null) state else state.copy(pendingClass = null, pendingSinceEpochMillis = null)
        }

        if (state.pendingClass != rawClass) {
            // Either nothing was pending, or a DIFFERENT class was pending
            // (e.g. established=HW, was pending UNKNOWN, now observes
            // POSSIBLE_UDP_OR_AWG_FILTERING instead) - this is a NEW
            // candidate transition, starting its own fresh residence timer.
            // The established value itself does not change yet.
            return state.copy(pendingClass = rawClass, pendingSinceEpochMillis = nowEpochMillis)
        }

        // The SAME differing class has now been observed continuously
        // since pendingSinceEpochMillis - check whether it has resided long
        // enough to be promoted.
        val pendingSince = state.pendingSinceEpochMillis ?: nowEpochMillis
        val residency = nowEpochMillis - pendingSince
        return if (residency >= minResidenceMillis) {
            State(establishedClass = rawClass, establishedAtEpochMillis = nowEpochMillis)
        } else {
            state
        }
    }
}
