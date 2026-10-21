package net.pocvpn.client.vpn.hysteria

import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** H2-GATE - the accept handoff behind acceptWithTimeout (the stats connection race). */
class Hysteria2ControlAcceptHandoffTest {

    @Test
    fun `a result produced before the waiter starts waiting is still delivered`() {
        // The tun2socks child dials its stats connection right after the ack,
        // so accept() can return before poll() runs - the case the old
        // SynchronousQueue handoff dropped.
        val produced = CountDownLatch(1)
        val discarded = CopyOnWriteArrayList<String>()
        val result = awaitHandoff(
            timeoutMillis = 2_000,
            threadName = "test-handoff",
            produce = { "stats-peer".also { produced.countDown() } },
            discardLate = { discarded += it },
            beforeWait = { assertTrue(produced.await(2, TimeUnit.SECONDS)); Thread.sleep(50) },
        )
        assertEquals("stats-peer", result)
        assertTrue(discarded.isEmpty())
    }

    @Test
    fun `a result that arrives after the timeout is discarded exactly once`() {
        val release = CountDownLatch(1)
        val discarded = CopyOnWriteArrayList<String>()
        val discardedSignal = CountDownLatch(1)
        val result = awaitHandoff(
            timeoutMillis = 50,
            threadName = "test-handoff",
            produce = { release.await(); "late-peer" },
            discardLate = { discarded += it; discardedSignal.countDown() },
        )
        assertNull(result)
        release.countDown()
        assertTrue(discardedSignal.await(2, TimeUnit.SECONDS))
        Thread.sleep(50)
        assertEquals(listOf("late-peer"), discarded.toList())
    }

    @Test
    fun `an IOException from produce yields null without waiting for the full timeout`() {
        val started = System.nanoTime()
        val result = awaitHandoff<String>(
            timeoutMillis = 5_000,
            threadName = "test-handoff",
            produce = { throw IOException("server socket closed") },
            discardLate = { throw AssertionError("nothing to discard") },
        )
        assertNull(result)
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 2_000)
    }

    @Test
    fun `immediate results are delivered on every attempt`() {
        repeat(200) {
            assertEquals(it, awaitHandoff(1_000, "test-handoff", produce = { it }, discardLate = {}))
        }
    }
}
