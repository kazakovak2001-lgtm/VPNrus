package net.pocvpn.client.smartconnect

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B28 review fix (blocker 2) - narrow, pure tests for RestrictionStabilizer
 * .advance(): this feature's own required cases (single transient flip
 * absorbed; sustained change eventually establishes; recovery is bounded,
 * not permanent; stale evidence still expires via the caller's own
 * classify() staleness, unaffected here; NO_NETWORK/CAPTIVE_PORTAL stay
 * immediate; alternating short-lived evidence never oscillates the
 * established value).
 */
class RestrictionStabilizerTest {

    private val hold = RestrictionStabilizer.DEFAULT_MIN_RESIDENCE_MILLIS

    @Test
    fun `a single transient UNKNOWN observation does not immediately flip an established POSSIBLE_HARD_WHITELIST decision`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass)
        // Reverting back to the established value before the hold window elapses clears the pending flip entirely.
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 2_000L)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass)
        assertEquals(null, state.pendingClass)
    }

    @Test
    fun `sustained UNKNOWN evidence for at least the hold window eventually clears an established POSSIBLE_HARD_WHITELIST`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass) // still held
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L + hold - 1)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass) // just under the window - still held
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L + hold)
        assertEquals(RestrictionClass.UNKNOWN, state.establishedClass) // window elapsed - promoted
    }

    @Test
    fun `sustained POSSIBLE_HARD_WHITELIST evidence for at least the hold window establishes the restricted state from UNKNOWN`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.UNKNOWN)
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 1_000L)
        assertEquals(RestrictionClass.UNKNOWN, state.establishedClass) // still held
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 1_000L + hold)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass) // window elapsed - established
    }

    @Test
    fun `recovery out of an established restricted state is bounded by the SAME hold window, never permanent`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        // A long time passes with sustained UNKNOWN - recovery still happens, is not permanently stuck at HARD_WHITELIST.
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L)
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L + hold)
        assertEquals(RestrictionClass.UNKNOWN, state.establishedClass)
    }

    @Test
    fun `NO_NETWORK takes effect immediately regardless of any established state or hold window`() {
        val state = RestrictionStabilizer.initial(0L, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        val next = RestrictionStabilizer.advance(state, RestrictionClass.NO_NETWORK, nowEpochMillis = 1L)
        assertEquals(RestrictionClass.NO_NETWORK, next.establishedClass)
    }

    @Test
    fun `CAPTIVE_PORTAL takes effect immediately, and leaving it (recovery) is also immediate`() {
        val state = RestrictionStabilizer.initial(0L, RestrictionClass.UNKNOWN)
        val entered = RestrictionStabilizer.advance(state, RestrictionClass.CAPTIVE_PORTAL, nowEpochMillis = 1L)
        assertEquals(RestrictionClass.CAPTIVE_PORTAL, entered.establishedClass)
        val left = RestrictionStabilizer.advance(entered, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 2L)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, left.establishedClass) // leaving CAPTIVE_PORTAL is immediate too, no hold window applied
    }

    @Test
    fun `alternating short-lived evidence, each reverting before the hold window elapses, never oscillates the established value`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.UNKNOWN)
        var now = 0L
        val quarterHold = hold / 4
        repeat(20) {
            now += quarterHold
            state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = now)
            now += quarterHold
            state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = now)
        }
        // Every flip away from UNKNOWN reverted before accumulating quarterHold*2 < hold of continuous residency - never promoted.
        assertEquals(RestrictionClass.UNKNOWN, state.establishedClass)
    }

    @Test
    fun `a different pending class than the one currently being tracked restarts its own fresh hold window`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.POSSIBLE_HARD_WHITELIST)
        state = RestrictionStabilizer.advance(state, RestrictionClass.UNKNOWN, nowEpochMillis = 1_000L)
        // A DIFFERENT non-established class appears before UNKNOWN's own hold window elapsed - this is a genuinely new pending observation, not a continuation.
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, nowEpochMillis = 1_000L + hold - 1)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass) // still held - the new pending class has not itself resided long enough
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, nowEpochMillis = 1_000L + hold - 1 + hold)
        assertEquals(RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, state.establishedClass) // now resided long enough itself
    }

    @Test
    fun `the very first observation any session makes is trusted immediately, with no artificial startup delay`() {
        val state = RestrictionStabilizer.initial(nowEpochMillis = 12_345L, firstObservedClass = RestrictionClass.POSSIBLE_HARD_WHITELIST)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass)
    }

    @Test
    fun `a custom minResidenceMillis is honored instead of the default`() {
        var state = RestrictionStabilizer.initial(0L, RestrictionClass.UNKNOWN)
        val shortHold = 5_000L
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 1_000L, minResidenceMillis = shortHold)
        assertEquals(RestrictionClass.UNKNOWN, state.establishedClass) // 0ms residency so far - not yet
        state = RestrictionStabilizer.advance(state, RestrictionClass.POSSIBLE_HARD_WHITELIST, nowEpochMillis = 1_000L + shortHold, minResidenceMillis = shortHold)
        assertEquals(RestrictionClass.POSSIBLE_HARD_WHITELIST, state.establishedClass)
    }
}
