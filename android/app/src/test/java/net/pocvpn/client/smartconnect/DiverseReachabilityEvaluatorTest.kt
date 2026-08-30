package net.pocvpn.client.smartconnect

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DiverseReachabilityEvaluatorTest {

    @Test
    fun `no probes yields null, never a guess`() {
        assertNull(DiverseReachabilityEvaluator.evaluate(emptyList()))
    }

    @Test
    fun `all reachable yields true`() {
        assertEquals(true, DiverseReachabilityEvaluator.evaluate(listOf(true, true, true)))
    }

    @Test
    fun `all unreachable yields false`() {
        assertEquals(false, DiverseReachabilityEvaluator.evaluate(listOf(false, false, false)))
    }

    @Test
    fun `strict majority reachable yields true`() {
        assertEquals(true, DiverseReachabilityEvaluator.evaluate(listOf(true, true, false)))
    }

    @Test
    fun `strict majority unreachable yields false`() {
        assertEquals(false, DiverseReachabilityEvaluator.evaluate(listOf(false, false, true)))
    }

    @Test
    fun `an exact tie counts as NOT reachable, the conservative direction`() {
        assertEquals(false, DiverseReachabilityEvaluator.evaluate(listOf(true, false)))
    }

    @Test
    fun `a single probe result is decisive on its own`() {
        assertEquals(true, DiverseReachabilityEvaluator.evaluate(listOf(true)))
        assertEquals(false, DiverseReachabilityEvaluator.evaluate(listOf(false)))
    }
}
