package net.pocvpn.client.vpn

import org.junit.Assert.assertTrue
import org.junit.Test

class ReconnectBackoffTest {

    @Test
    fun `delay grows with attempt number, before hitting the cap`() {
        val noJitter = { 0.0 }
        val d1 = ReconnectBackoff.delayForAttempt(1, noJitter)
        val d2 = ReconnectBackoff.delayForAttempt(2, noJitter)
        val d3 = ReconnectBackoff.delayForAttempt(3, noJitter)
        assertTrue(d1 < d2)
        assertTrue(d2 < d3)
    }

    @Test
    fun `delay never exceeds max plus jitter, even for very large attempt numbers`() {
        val maxJitter = { 1.0 }
        val delay = ReconnectBackoff.delayForAttempt(1000, maxJitter)
        val jitterCeiling = (ReconnectBackoff.MAX_DELAY_MS * 1.2).toLong()
        assertTrue("delay=$delay must be <= $jitterCeiling", delay <= jitterCeiling)
    }

    @Test
    fun `delay is always at least the base delay`() {
        val noJitter = { 0.0 }
        val delay = ReconnectBackoff.delayForAttempt(1, noJitter)
        assertTrue(delay >= ReconnectBackoff.BASE_DELAY_MS)
    }

    @Test(expected = IllegalArgumentException::class)
    fun `attempt below 1 is rejected`() {
        ReconnectBackoff.delayForAttempt(0)
    }
}
