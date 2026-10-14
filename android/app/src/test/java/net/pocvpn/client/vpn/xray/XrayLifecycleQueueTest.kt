package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class XrayLifecycleQueueTest {

    @Test
    fun `commands run one at a time in enqueue order - STOP(N) before START(N+1)`() {
        val scope = TestScope(StandardTestDispatcher())
        val log = mutableListOf<String>()
        val startN = CompletableDeferred<Unit>()
        val queue = XrayLifecycleQueue(scope)

        queue.enqueue { log += "start N begin"; startN.await(); log += "start N end" }
        queue.enqueue { log += "stop N" }
        queue.enqueue { log += "start N+1" }
        scope.runCurrent()
        assertEquals(listOf("start N begin"), log) // stop N and start N+1 wait for start N

        startN.complete(Unit)
        scope.runCurrent()
        assertEquals(listOf("start N begin", "start N end", "stop N", "start N+1"), log)
        scope.cancel()
    }

    @Test
    fun `a failing command is reported and later commands still run`() {
        val scope = TestScope(StandardTestDispatcher())
        val failures = mutableListOf<Throwable>()
        val log = mutableListOf<String>()
        val queue = XrayLifecycleQueue(scope) { failures += it }

        queue.enqueue { error("boom") }
        queue.enqueue { log += "stop" }
        scope.runCurrent()

        assertEquals(1, failures.size)
        assertEquals(listOf("stop"), log)
        scope.cancel()
    }
}
