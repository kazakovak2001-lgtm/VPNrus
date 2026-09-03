package net.pocvpn.client.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B30B - the pure bookkeeping [AndroidReconnectManager] relies on to decide
 * when to fire onNetworkLost/onNetworkAvailable from a stream of per-network
 * onAvailable/onLost events. Covers Phase C's own explicit scenarios: a
 * WiFi<->cellular handover where a usable network is available throughout
 * must never report "lost", while losing the ONLY available network (total
 * loss) must.
 */
class NetworkAvailabilitySetTest {

    @Test
    fun `first network becoming available reports a transition`() {
        val set = NetworkAvailabilitySet()
        assertTrue(set.markAvailable("wifi"))
    }

    @Test
    fun `a second concurrently-available network reports no new transition`() {
        val set = NetworkAvailabilitySet()
        set.markAvailable("wifi")
        assertFalse(set.markAvailable("cellular"))
    }

    @Test
    fun `losing one of two available networks reports no loss transition - WiFi to mobile handover`() {
        val set = NetworkAvailabilitySet()
        set.markAvailable("wifi")
        set.markAvailable("cellular")

        assertFalse("losing WiFi while cellular is still up must not report total loss", set.markLost("wifi"))
        assertFalse(set.isEmpty())
    }

    @Test
    fun `losing the ONLY available network reports a loss transition - total loss`() {
        val set = NetworkAvailabilitySet()
        set.markAvailable("wifi")

        assertTrue(set.markLost("wifi"))
        assertTrue(set.isEmpty())
    }

    @Test
    fun `losing a network that was never marked available is a no-op, not a false loss transition`() {
        val set = NetworkAvailabilitySet()
        assertFalse(set.markLost("wifi"))
        assertTrue(set.isEmpty())
    }

    @Test
    fun `network returning after total loss reports a fresh availability transition`() {
        val set = NetworkAvailabilitySet()
        set.markAvailable("wifi")
        set.markLost("wifi")

        assertTrue("network coming back after a genuine total loss must report available again", set.markAvailable("cellular"))
    }

    @Test
    fun `mobile to WiFi handover - losing mobile while WiFi is already up reports no loss`() {
        val set = NetworkAvailabilitySet()
        set.markAvailable("cellular")
        set.markAvailable("wifi")

        assertFalse(set.markLost("cellular"))
        assertFalse(set.isEmpty())
    }
}
