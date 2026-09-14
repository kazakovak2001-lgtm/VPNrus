package net.pocvpn.client.reachability

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GenerationFenceTest {
    @Test
    fun `older completion is ignored after newer generation starts`() {
        val fence = GenerationFence()
        val first = fence.begin()
        val second = fence.begin()
        assertFalse(fence.isCurrent(first))
        assertTrue(fence.isCurrent(second))
    }

    @Test
    fun `stale failure cannot replace newer successful generation`() {
        val fence = GenerationFence()
        val first = fence.begin()
        val second = fence.begin()
        var published = "success"
        if (fence.isCurrent(first)) published = "stale failure"
        assertTrue(fence.isCurrent(second))
        assertTrue(published == "success")
    }

    @Test
    fun `cancellation followed by a new attempt fences the cancelled callback`() {
        val fence = GenerationFence()
        val cancelled = fence.begin()
        val replacement = fence.begin()
        assertFalse(fence.isCurrent(cancelled))
        assertTrue(fence.isCurrent(replacement))
    }
}
