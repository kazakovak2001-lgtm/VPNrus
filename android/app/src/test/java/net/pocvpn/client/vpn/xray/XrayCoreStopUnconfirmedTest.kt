@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 3H - an unconfirmed core stop never reads as "stopped" and blocks every new core on the shared
 * runtime until a later stop is confirmed by [XrayCoreRuntime.isRunning]. The runtime mirrors the
 * pinned wrapper's contract (AndroidLibXrayLite c634d1b): StopLoop() is idempotent, and its
 * shutdown is what clears IsRunning. All hold points are explicit flags - no timing.
 */
class XrayCoreStopUnconfirmedTest {

    private val profile = XrayProfile(
        server = "152.70.43.1", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
        fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    private class Repo(private val profile: XrayProfile) : XrayProfileRepository {
        override suspend fun getProfileOrNull(): XrayProfile? = profile
        override suspend fun saveProfile(profile: XrayProfile) {}
        override suspend fun clearProfile() {}
    }

    /**
     * [stuck]: stopLoop() throws and the core keeps running. [throwAfterStop]: the core really
     * stops, then stopLoop() throws anyway. [failMeasure]: the post-start confirmation fails.
     */
    private class Runtime(val inner: FakeXrayCoreRuntime = FakeXrayCoreRuntime()) : XrayCoreRuntime by inner {
        var stuck = false
        var throwAfterStop = false
        var failMeasure = false
        var stopCalls = 0
        override fun stopLoop() {
            stopCalls++
            if (stuck) throw IllegalStateException("stuck")
            inner.stopLoop()
            if (throwAfterStop) throw IllegalStateException("late")
        }
        override fun measureDelay(url: String): Long {
            if (failMeasure) throw IllegalStateException("probe failed")
            return inner.measureDelay(url)
        }
    }

    private class Counters { var establish = 0; var close = 0; var built = 0 }

    private fun controller(rt: XrayCoreRuntime, state: XrayCoreStopState, n: Counters, scope: CoroutineScope) =
        XrayCoreController(
            repository = Repo(profile), coreRuntime = rt, novaPackageId = "net.pocvpn.client.test",
            ensureCoreEnvInitialized = {}, establishTun = { n.establish++; 42 }, closeTun = { n.close++ },
            probeScope = scope, stopState = state,
        )

    private fun coordinator(rt: XrayCoreRuntime, state: XrayCoreStopState, n: Counters, scope: CoroutineScope) =
        NovaXrayServiceLifecycleCoordinator { n.built++; controller(rt, state, n, scope) }

    private val a = EndpointId("gateway-a")
    private val b = EndpointId("gateway-b")

    // 1 + 3. stopLoop fails and the core still runs: unconfirmed, no Stopped, no new START.
    @Test
    fun `stuck stop is unconfirmed after one bounded retry and blocks every later START`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        assertEquals(XrayCoreStartOutcome.Started, c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L))
        rt.stuck = true

        val stopped = c.stopSession(expectedSessionId = 1L)

        assertTrue(stopped.outcome.didTeardown); assertTrue(stopped.outcome.unconfirmed)
        assertEquals(2, rt.stopCalls) // first call + exactly one retry, never more
        assertTrue(teardownEventFor(stopped) is XrayRuntimeEvent.Failed)
        assertEquals("IllegalStateException", state.unconfirmedReason)

        for (id in 2L..3L) {
            val again = c.start(a, TransportKind.XRAY_REALITY, sessionId = id)
            assertTrue("unexpected $again", again is XrayCoreStartOutcome.StopUnconfirmed)
        }
        assertEquals(1, n.establish); assertEquals(1, rt.inner.startLoopCallCount)
        assertTrue(rt.inner.isRunning)
    }

    // 2. stopLoop throws, but the runtime confirms the core is down.
    @Test
    fun `throwing stop whose core reads stopped is a confirmed stop`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L)
        rt.throwAfterStop = true

        val stopped = c.stopSession(expectedSessionId = 1L)

        assertTrue(stopped.outcome.didTeardown); assertFalse(stopped.outcome.unconfirmed)
        assertEquals("IllegalStateException", stopped.outcome.stopLoopFailureReason)
        assertEquals(1, rt.stopCalls) // no retry once the core reads stopped
        assertEquals(XrayRuntimeEvent.Stopped(1L), teardownEventFor(stopped))
        assertNull(state.unconfirmedReason)
        rt.throwAfterStop = false
        assertEquals(XrayCoreStartOutcome.Started, c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L))
    }

    @Test
    fun `a later STOP that confirms the stop lifts the block`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L)
        rt.stuck = true
        c.stopSession(expectedSessionId = 1L)
        rt.stuck = false

        val retry = c.stopSession(expectedSessionId = 1L) // the best-effort STOP after Failed(1)

        assertTrue(retry.outcome.didTeardown); assertFalse(retry.outcome.unconfirmed)
        assertNull(retry.sessionId) // no session runs any more: nothing to report as Stopped
        assertNull(teardownEventFor(retry))
        assertFalse(rt.inner.isRunning); assertNull(state.unconfirmedReason)
        assertEquals(XrayCoreStartOutcome.Started, c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L))
        assertEquals(1, rt.inner.stopLoopCallCount); assertEquals(2, rt.inner.startLoopCallCount)
    }

    // 4. Endpoint switch after an unconfirmed stop.
    @Test
    fun `endpoint switch over an unconfirmed stop builds no new controller and starts nothing`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L)
        rt.stuck = true

        val outcome = c.start(b, TransportKind.XRAY_REALITY) // no session id: the endpoint-switch path, not supersede

        assertTrue("unexpected $outcome", outcome is XrayCoreStartOutcome.StopUnconfirmed)
        assertEquals(1, n.built); assertEquals(1, n.establish); assertEquals(1, rt.inner.startLoopCallCount)
        assertTrue(rt.inner.isRunning)
        // The old controller stays cached: a STOP still reaches the stuck core.
        rt.stuck = false
        assertFalse(c.stopSession().outcome.unconfirmed)
        assertFalse(rt.inner.isRunning)
    }

    @Test
    fun `a fresh controller on the same runtime cannot bypass the shared state`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val first = controller(rt, state, n, this)
        first.requestStart()
        rt.stuck = true
        assertTrue(first.requestStop().unconfirmed)

        val second = controller(rt, state, n, this).requestStart()

        assertTrue("unexpected $second", second is XrayCoreStartOutcome.StopUnconfirmed)
        assertEquals(1, n.establish); assertEquals(1, rt.inner.startLoopCallCount)
    }

    // 5. RemoteUnconfirmed whose own stop is unconfirmed.
    @Test
    fun `RemoteUnconfirmed with an unconfirmed stop keeps later STARTs blocked`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        rt.failMeasure = true; rt.stuck = true

        val first = c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L)

        assertTrue("unexpected $first", first is XrayCoreStartOutcome.RemoteUnconfirmed)
        assertTrue((first as XrayCoreStartOutcome.RemoteUnconfirmed).reason.contains("core stop unconfirmed"))
        assertEquals(1, n.close) // the tun is still released
        rt.failMeasure = false
        val second = c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L)
        assertTrue("unexpected $second", second is XrayCoreStartOutcome.StopUnconfirmed)
        assertEquals(1, n.establish); assertEquals(1, rt.inner.startLoopCallCount)
    }

    // 6. teardownAndPublish's event choice.
    @Test
    fun `teardown event is Stopped only for a confirmed stop`() {
        fun s(outcome: XrayCoreStopOutcome, id: Long?) = NovaXrayServiceLifecycleCoordinator.StoppedSession(outcome, id)
        assertEquals(XrayRuntimeEvent.Stopped(7L), teardownEventFor(s(XrayCoreStopOutcome(didTeardown = true), 7L)))
        val failed = teardownEventFor(s(XrayCoreStopOutcome(true, "IllegalStateException", unconfirmed = true), 7L))
        assertTrue(failed is XrayRuntimeEvent.Failed); assertEquals(7L, failed!!.sessionId)
        assertNull(teardownEventFor(s(XrayCoreStopOutcome(true, "IllegalStateException", unconfirmed = true), null)))
    }

    // Supersede with a confirmed-but-throwing stop is a real stop (3F refused it as "did not stop").
    @Test
    fun `supersede over a throwing but confirmed stop starts the new session`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val n = Counters()
        val c = coordinator(rt, state, n, this)
        c.start(a, TransportKind.XRAY_REALITY, sessionId = 1L)
        rt.throwAfterStop = true
        val superseded = mutableListOf<Long>()

        val outcome = c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L, onSuperseded = { superseded += it })

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(listOf(1L), superseded)
    }

    // 3J - the relay-health watchdog's stop runs under the coordinator lock.

    /** One tun at a time, like NovaXrayVpnService.tunInterface: closeTun closes whatever is current. */
    private class Tun {
        var current: Int? = null
        val opened = mutableListOf<Int>()
        val closed = mutableListOf<Int>()
        fun establish(): Int = (100 + opened.size).also { opened += it; current = it }
        fun close() { current?.let { closed += it }; current = null }
    }

    private fun tunCoordinator(rt: XrayCoreRuntime, state: XrayCoreStopState, tun: Tun, scope: CoroutineScope) =
        NovaXrayServiceLifecycleCoordinator {
            XrayCoreController(
                repository = Repo(profile), coreRuntime = rt, novaPackageId = "net.pocvpn.client.test",
                ensureCoreEnvInitialized = {}, establishTun = { tun.establish() }, closeTun = { tun.close() },
                probeScope = scope, stopState = state,
            )
        }

    /**
     * Session 1 runs relayed; its watchdog reaches the failure threshold and stops it, then parks
     * in onRelayHealthLost (still holding the coordinator lock) on [hold]. Returns the event log.
     */
    private suspend fun kotlinx.coroutines.test.TestScope.watchdogStopsSessionOneAndParks(
        c: NovaXrayServiceLifecycleCoordinator,
        rt: Runtime,
        hold: kotlinx.coroutines.CompletableDeferred<Unit>,
    ): MutableList<String> {
        val events = mutableListOf<String>()
        val first = c.start(
            a, TransportKind.XRAY_REALITY,
            confirmationContext = RemoteConfirmationContext.Relayed("152.70.43.1"),
            sessionId = 1L,
            onRelayHealthLost = { events += "Failed(1)"; hold.await() },
        )
        assertEquals(XrayCoreStartOutcome.Started, first); events += "Started(1)"
        rt.failMeasure = true
        repeat(2) { advanceTimeBy(20_001L); runCurrent() } // two consecutive probe failures
        rt.failMeasure = false
        return events
    }

    @Test
    fun `START N+1 waits for the watchdog stop of N and runs after a confirmed stop`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val tun = Tun()
        val c = tunCoordinator(rt, state, tun, this)
        val hold = kotlinx.coroutines.CompletableDeferred<Unit>()
        val events = watchdogStopsSessionOneAndParks(c, rt, hold)
        assertEquals(listOf("Started(1)", "Failed(1)"), events)
        assertEquals(1, rt.inner.stopLoopCallCount); assertEquals(listOf(100), tun.closed)

        val second = async {
            c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L, onSuperseded = { events += "Stopped($it)" })
        }
        runCurrent()
        assertFalse("START must wait for the watchdog's locked stop", second.isCompleted)
        assertEquals(listOf(100), tun.opened); assertEquals(1, rt.inner.startLoopCallCount)

        hold.complete(Unit); runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, second.await()); events += "Started(2)"
        assertEquals(listOf("Started(1)", "Failed(1)", "Started(2)"), events) // no Stopped(1): it already ended as Failed(1)
        assertEquals(listOf(100, 101), tun.opened)
        assertEquals(listOf(100), tun.closed) // the old stop never closed the new tun
        assertEquals(101, tun.current)
        assertEquals(2, rt.inner.startLoopCallCount); assertTrue(rt.inner.isRunning)
        assertEquals(2L, c.stopSession(expectedSessionId = 2L).sessionId)
    }

    @Test
    fun `START N+1 waiting behind an unconfirmed watchdog stop creates no tun and no Started`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val tun = Tun()
        val c = tunCoordinator(rt, state, tun, this)
        val hold = kotlinx.coroutines.CompletableDeferred<Unit>()
        rt.stuck = true // only stopLoop is stuck; the probes still run
        val events = watchdogStopsSessionOneAndParks(c, rt, hold)
        assertEquals(listOf("Started(1)", "Failed(1)"), events) // reported as a failure, never Stopped(1)
        assertEquals(2, rt.stopCalls); assertTrue(rt.inner.isRunning)
        assertEquals("IllegalStateException", state.unconfirmedReason)

        val second = async {
            c.start(a, TransportKind.XRAY_REALITY, sessionId = 2L, onSuperseded = { events += "Stopped($it)" })
        }
        runCurrent()
        assertFalse(second.isCompleted)

        hold.complete(Unit); runCurrent()

        val outcome = second.await()
        assertTrue("unexpected $outcome", outcome is XrayCoreStartOutcome.StopUnconfirmed)
        assertEquals(listOf("Started(1)", "Failed(1)"), events)
        assertEquals(listOf(100), tun.opened); assertEquals(listOf(100), tun.closed)
        assertEquals(1, rt.inner.startLoopCallCount)
    }

    @Test
    fun `an explicit STOP before the watchdog threshold cancels the watchdog - it never stops or reports`() = runTest {
        val rt = Runtime(); val state = XrayCoreStopState(); val tun = Tun()
        val c = tunCoordinator(rt, state, tun, this)
        val events = mutableListOf<String>()
        c.start(
            a, TransportKind.XRAY_REALITY,
            confirmationContext = RemoteConfirmationContext.Relayed("152.70.43.1"),
            sessionId = 1L,
            onRelayHealthLost = { events += "Failed(1)" },
        )
        rt.failMeasure = true
        advanceTimeBy(20_001L); runCurrent() // first failure only
        assertEquals(1L, c.stopSession(expectedSessionId = 1L).sessionId) // explicit STOP wins: Stopped(1)
        advanceTimeBy(60_000L); runCurrent()

        assertTrue(events.isEmpty()) // the cancelled watchdog never reports after Stopped(1)
        assertEquals(1, rt.inner.stopLoopCallCount); assertEquals(listOf(100), tun.closed)
    }
}
