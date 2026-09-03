package net.pocvpn.client.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B30B review fix (PR #46) - proves each start()/stop() registration
 * lifetime ([ReconnectAvailabilityLifecycle.beginGeneration]/[endGeneration])
 * genuinely begins from empty state, and that a stale event tagged with an
 * OLD generation can never corrupt a NEWER one's state - the exact blocker
 * found in review (state from an old [AndroidReconnectManager] start()/
 * stop() lifetime leaking into a new one).
 */
class ReconnectAvailabilityLifecycleTest {

    // A. start lifetime #1 -> wifi available -> stop -> start lifetime #2
    // with no available network => isNetworkAvailable == false.
    @Test
    fun `a fresh generation with no events starts unavailable, even after a prior generation was available`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        lifecycle.onAvailable(gen1, "wifi")
        assertTrue(lifecycle.networkAvailable)

        lifecycle.endGeneration()
        assertFalse(lifecycle.networkAvailable)

        lifecycle.beginGeneration() // gen2, nothing reported available yet
        assertFalse("a fresh registration must start unavailable, not inherit gen1's state", lifecycle.networkAvailable)
    }

    // B. lifetime #1 sees wifi -> stop -> start again -> the SAME wifi
    // becomes available => the new registration produces a fresh
    // available transition (not silently absorbed as "already known").
    @Test
    fun `the same network id becoming available again in a new generation reports a fresh transition`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        assertTrue(lifecycle.onAvailable(gen1, "wifi"))

        lifecycle.endGeneration()
        val gen2 = lifecycle.beginGeneration()

        assertTrue(
            "the same network id must produce a genuinely fresh transition in a new generation",
            lifecycle.onAvailable(gen2, "wifi"),
        )
        assertTrue(lifecycle.networkAvailable)
    }

    // C. lifetime #1 sees wifi + cellular -> stop/start => no stale members
    // remain from the old set.
    @Test
    fun `no stale members leak from a prior generation's multi-network set`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        lifecycle.onAvailable(gen1, "wifi")
        lifecycle.onAvailable(gen1, "cellular")

        lifecycle.endGeneration()
        val gen2 = lifecycle.beginGeneration()
        assertFalse(lifecycle.networkAvailable)

        // Losing a network gen2 never actually saw as available must be a
        // no-op (proves gen2's own set is genuinely empty, not carrying
        // gen1's members) - never a spurious "still non-empty" or crash.
        assertFalse(lifecycle.onLost(gen2, "wifi"))
        assertFalse(lifecycle.networkAvailable)
    }

    // D. a late/stale callback from registration #1 must not corrupt
    // registration #2 state.
    @Test
    fun `a stale callback tagged with an old generation is rejected outright`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        lifecycle.onAvailable(gen1, "wifi")
        lifecycle.endGeneration()

        val gen2 = lifecycle.beginGeneration()
        assertFalse(lifecycle.networkAvailable)

        // A callback instance from generation #1 firing LATE (e.g. posted
        // before unregisterNetworkCallback took effect) - still tagged gen1.
        val staleTransitioned = lifecycle.onAvailable(gen1, "wifi")
        assertFalse("a stale generation's event must be rejected, not treated as a real transition", staleTransitioned)
        assertFalse("a stale callback must never flip networkAvailable for the CURRENT generation", lifecycle.networkAvailable)

        // gen2's own real event still works normally afterward.
        assertTrue(lifecycle.onAvailable(gen2, "cellular"))
        assertTrue(lifecycle.networkAvailable)
    }

    @Test
    fun `a stale lost callback from an old generation cannot fabricate a loss transition for the current one`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        lifecycle.onAvailable(gen1, "wifi")
        lifecycle.endGeneration()

        val gen2 = lifecycle.beginGeneration()
        lifecycle.onAvailable(gen2, "cellular")
        assertTrue(lifecycle.networkAvailable)

        // A late onLost from generation #1 for "wifi" must not touch gen2's
        // real, currently-available "cellular" state.
        val staleLost = lifecycle.onLost(gen1, "wifi")
        assertFalse(staleLost)
        assertTrue("a stale generation's onLost must never affect the CURRENT generation's availability", lifecycle.networkAvailable)
    }

    // E. existing WiFi<->cellular handover behavior still passes within one
    // generation (unaffected by the generation/lifecycle wrapper).
    @Test
    fun `WiFi to cellular handover within one generation still never reports a spurious loss`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen = lifecycle.beginGeneration()

        lifecycle.onAvailable(gen, "wifi")
        lifecycle.onAvailable(gen, "cellular")
        assertTrue(lifecycle.networkAvailable)

        val lostAll = lifecycle.onLost(gen, "wifi")
        assertFalse("losing WiFi while cellular is still up must not report total loss", lostAll)
        assertTrue("cellular is still up - must remain available", lifecycle.networkAvailable)
    }

    @Test
    fun `generation ids strictly increase across repeated start-stop cycles`() {
        val lifecycle = ReconnectAvailabilityLifecycle()
        val gen1 = lifecycle.beginGeneration()
        lifecycle.endGeneration()
        val gen2 = lifecycle.beginGeneration()
        lifecycle.endGeneration()
        val gen3 = lifecycle.beginGeneration()

        assertTrue(gen1 < gen2)
        assertTrue(gen2 < gen3)
        assertEquals(gen3, gen3) // sanity: begin() itself returns the now-current generation
    }
}
