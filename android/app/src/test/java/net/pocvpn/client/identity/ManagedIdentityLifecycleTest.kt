package net.pocvpn.client.identity

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ManagedIdentityLifecycleTest {

    /** Two consumers built around ONE injected instance - the intended MainViewModel/VpnController sharing. */
    private class Consumer(private val lifecycle: ManagedIdentityLifecycle) {
        suspend fun <T> critical(block: suspend () -> T): T = lifecycle.withLock(block)
    }

    @Test
    fun `consumers sharing one instance are mutually exclusive`() = runBlocking {
        val lifecycle = ManagedIdentityLifecycle()
        val a = Consumer(lifecycle)
        val b = Consumer(lifecycle)
        val gate = CompletableDeferred<Unit>()
        val aEntered = CompletableDeferred<Unit>()

        val first = async { a.critical { aEntered.complete(Unit); gate.await(); "a" } }
        aEntered.await()
        val second = async { b.critical { "b" } }
        yield()
        assertFalse("b must wait while a holds L", second.isCompleted)
        assertTrue(lifecycle.isLocked)

        gate.complete(Unit)
        assertEquals("a", first.await())
        assertEquals("b", second.await())
        assertFalse(lifecycle.isLocked)
    }

    @Test
    fun `separately constructed instances are independent - no global singleton`() = runBlocking {
        val one = ManagedIdentityLifecycle()
        val two = ManagedIdentityLifecycle()
        assertNotSame(one, two)
        val gate = CompletableDeferred<Unit>()
        val held = launch { one.withLock { gate.await() } }
        yield()
        assertTrue(one.isLocked)
        assertEquals("free", two.withLock { "free" }) // not blocked by `one`
        gate.complete(Unit)
        held.join()
    }

    @Test
    fun `L is released after an exception`() = runBlocking {
        val lifecycle = ManagedIdentityLifecycle()
        assertThrows(IllegalStateException::class.java) {
            runBlocking { lifecycle.withLock { throw IllegalStateException("boom") } }
        }
        assertFalse(lifecycle.isLocked)
        assertEquals(1, lifecycle.withLock { 1 })
    }

    @Test
    fun `L is released after cancellation`() = runBlocking {
        val lifecycle = ManagedIdentityLifecycle()
        val entered = CompletableDeferred<Unit>()
        val job = launch { lifecycle.withLock { entered.complete(Unit); CompletableDeferred<Unit>().await() } }
        entered.await()
        assertTrue(lifecycle.isLocked)
        job.cancel(CancellationException("test"))
        job.join()
        assertFalse(lifecycle.isLocked)
    }

    @Test
    fun `L is released after an early return`() = runBlocking {
        val lifecycle = ManagedIdentityLifecycle()
        suspend fun earlyReturn(): Int = lifecycle.withLock { return@withLock 7 }
        assertEquals(7, earlyReturn())
        assertFalse(lifecycle.isLocked)
    }
}
