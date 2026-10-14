@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
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
import org.junit.Assert.fail
import org.junit.Test

/**
 * 3F - deterministic coordinator tests for the superseding START (variant C). Hold points come from
 * [GateRepo] (the profile read happens in requestStart, i.e. AFTER the old core was stopped and
 * onSuperseded ran), never from timing. The `log` mirrors what NovaXrayVpnService publishes, in order:
 * "Stopped(old)" comes from onSuperseded, "start(id)=Outcome" is the Started/Failed the service
 * derives from the outcome. The service itself (Android Service) is not exercised here.
 */
class NovaXrayServiceLifecycleSupersedeFailureTest {

    private val validProfile = XrayProfile(
        server = "152.70.43.1", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
        fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    /** Suspends profile reads on [gate] while one is set - a hold point inside requestStart. */
    private class GateRepo(private val profile: XrayProfile) : XrayProfileRepository {
        @Volatile var gate: CompletableDeferred<Unit>? = null
        override suspend fun getProfileOrNull(): XrayProfile? {
            gate?.await()
            return profile
        }
        override suspend fun saveProfile(profile: XrayProfile) {}
        override suspend fun clearProfile() {}
    }

    /** Wraps the fake; the flags make the NEXT core operations fail. stopLoop failing leaves the inner core running (as a real stuck core would). */
    private class FlakyRuntime(val inner: FakeXrayCoreRuntime = FakeXrayCoreRuntime()) : XrayCoreRuntime by inner {
        var failStarts = false
        var failStops = false
        var failMeasure = false
        override fun startLoop(configContent: String, tunFd: Int) {
            if (failStarts) throw IllegalStateException("core refused to start")
            inner.startLoop(configContent, tunFd)
        }
        override fun stopLoop() {
            if (failStops) throw IllegalStateException("core refused to stop")
            inner.stopLoop()
        }
        override fun measureDelay(url: String): Long {
            if (failMeasure) throw IllegalStateException("probe failed")
            return inner.measureDelay(url)
        }
    }

    private val endpointA = EndpointId("gateway-a")

    private fun coordinatorFor(runtime: XrayCoreRuntime, repo: XrayProfileRepository, scope: kotlinx.coroutines.CoroutineScope) =
        NovaXrayServiceLifecycleCoordinator {
            XrayCoreController(
                repository = repo,
                coreRuntime = runtime,
                novaPackageId = "net.pocvpn.client.test",
                ensureCoreEnvInitialized = {},
                establishTun = { 42 },
                closeTun = {},
                probeScope = scope,
            )
        }

    private suspend fun NovaXrayServiceLifecycleCoordinator.go(
        id: Long?,
        log: MutableList<String>,
        failures: MutableList<Throwable> = mutableListOf(),
    ): XrayCoreStartOutcome {
        val outcome = start(
            endpointA, TransportKind.XRAY_REALITY, sessionId = id,
            onSuperseded = { log += "Stopped($it)" },
            onSupersededFailed = { failures += it },
        )
        log += "start($id)=${outcome::class.simpleName}"
        return outcome
    }

    // 1. Held exchange 900 -> 901 with STOP(900), STOP(901), START(902) queued behind it.
    @Test
    fun `held exchange - queued STOP 900, STOP 901 and START 902 resolve in arrival order`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        assertEquals(XrayCoreStartOutcome.Started, c.go(900L, log))
        val gate = CompletableDeferred<Unit>(); repo.gate = gate

        val s901 = async { c.go(901L, log) }
        runCurrent()
        assertEquals(listOf("start(900)=Started", "Stopped(900)"), log) // old core already stopped and reported
        assertEquals(1, rt.stopLoopCallCount)
        assertEquals(1, rt.startLoopCallCount) // the new core has NOT started yet
        val stop900 = async { c.stopSession(expectedSessionId = 900L) }
        val stop901 = async { c.stopSession(expectedSessionId = 901L) }
        val s902 = async { c.go(902L, log) }
        runCurrent()
        assertFalse(s901.isCompleted || stop900.isCompleted || stop901.isCompleted || s902.isCompleted)

        gate.complete(Unit); runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, s901.await())
        val late = stop900.await()
        assertFalse(late.outcome.didTeardown); assertEquals(901L, late.otherRunningSessionId)
        val own = stop901.await()
        assertTrue(own.outcome.didTeardown); assertEquals(901L, own.sessionId)
        assertEquals(XrayCoreStartOutcome.Started, s902.await()) // runs fresh: nothing was running after STOP(901)
        assertEquals(listOf("start(900)=Started", "Stopped(900)", "start(901)=Started", "start(902)=Started"), log)
        assertEquals(3, rt.startLoopCallCount); assertEquals(2, rt.stopLoopCallCount); assertTrue(rt.isRunning)
        assertEquals(902L, c.stopSession(expectedSessionId = 902L).sessionId)
    }

    // 2. Reversed arrival: 902 holds the lock, 901 arrives later and must not take over.
    @Test
    fun `reversed arrival - the older START 901 never takes over from 902`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        val gate = CompletableDeferred<Unit>(); repo.gate = gate

        val s902 = async { c.go(902L, log) }
        runCurrent()
        val s901 = async { c.go(901L, log) }
        runCurrent()
        gate.complete(Unit); runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, s902.await())
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, s901.await())
        assertEquals(listOf("start(902)=Started", "start(901)=AlreadyRunning"), log)
        assertEquals(1, rt.startLoopCallCount); assertEquals(0, rt.stopLoopCallCount)
        val stale = c.stopSession(expectedSessionId = 901L)
        assertFalse(stale.outcome.didTeardown); assertEquals(902L, stale.otherRunningSessionId)
        assertTrue(rt.isRunning)
        assertEquals(902L, c.stopSession(expectedSessionId = 902L).sessionId)
    }

    // 3. Untagged stop while the exchange is held.
    @Test
    fun `untagged stop queued behind a held exchange stops the NEW core exactly once`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        c.go(900L, log)
        val gate = CompletableDeferred<Unit>(); repo.gate = gate
        val s901 = async { c.go(901L, log) }
        runCurrent()
        val untagged = async { c.stopSession() }
        runCurrent()
        assertFalse(untagged.isCompleted)

        gate.complete(Unit); runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, s901.await())
        val stopped = untagged.await()
        assertTrue(stopped.outcome.didTeardown); assertEquals(901L, stopped.sessionId)
        assertFalse(rt.isRunning); assertEquals(2, rt.stopLoopCallCount)
        assertEquals(listOf("start(900)=Started", "Stopped(900)", "start(901)=Started"), log)
    }

    @Test
    fun `untagged stop queued behind a held exchange whose new start fails is a harmless no-op`() = runTest {
        val rt = FlakyRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        c.go(900L, log)
        val gate = CompletableDeferred<Unit>(); repo.gate = gate
        val s901 = async { c.go(901L, log) }
        runCurrent()
        val untagged = async { c.stopSession() }
        runCurrent()
        rt.failStarts = true

        gate.complete(Unit); runCurrent()

        assertTrue(s901.await() is XrayCoreStartOutcome.CoreStartFailed)
        val stopped = untagged.await()
        assertFalse(stopped.outcome.didTeardown); assertNull(stopped.sessionId)
        assertFalse(rt.inner.isRunning)
        assertEquals(listOf("start(900)=Started", "Stopped(900)", "start(901)=CoreStartFailed"), log)
    }

    // 4. stopLoop of the old core fails.
    @Test
    fun `stopLoop failure of the old core - no second core, no Stopped event, START fails with the reason`() = runTest {
        val rt = FlakyRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        c.go(900L, log)
        rt.failStops = true

        val outcome = c.go(901L, log)

        assertEquals(XrayCoreStartOutcome.CoreStartFailed("previous session did not stop: IllegalStateException"), outcome)
        assertEquals(listOf("start(900)=Started", "start(901)=CoreStartFailed"), log) // no Stopped(900), no Started(901)
        assertEquals(1, rt.inner.startLoopCallCount) // the second core was never started
        assertTrue("the old core really may still run - nothing claims otherwise", rt.inner.isRunning)
        // 3H - the unconfirmed stop is retried by the next STOP and stays unconfirmed while the core runs.
        val retry = c.stopSession().outcome
        assertTrue(retry.didTeardown); assertTrue(retry.unconfirmed)
        assertTrue(rt.inner.isRunning)
    }

    // 5. Exception from the publishing callback.
    @Test
    fun `an ordinary callback exception is reported and the new START still runs`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile)
        val c = coordinatorFor(rt, repo, this)
        c.start(endpointA, TransportKind.XRAY_REALITY, sessionId = 900L)
        val failures = mutableListOf<Throwable>()

        val outcome = c.start(
            endpointA, TransportKind.XRAY_REALITY, sessionId = 901L,
            onSuperseded = { throw IllegalStateException("broadcast failed") },
            onSupersededFailed = { failures += it },
        )

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, failures.size); assertTrue(failures[0] is IllegalStateException)
        assertEquals(2, rt.startLoopCallCount); assertEquals(1, rt.stopLoopCallCount) // old core really stopped, new one really started
        assertEquals(901L, c.stopSession(expectedSessionId = 901L).sessionId)
    }

    @Test
    fun `a CancellationException from the callback propagates, starts nothing and leaves the lock free`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile)
        val c = coordinatorFor(rt, repo, this)
        c.start(endpointA, TransportKind.XRAY_REALITY, sessionId = 900L)
        val failures = mutableListOf<Throwable>()

        try {
            c.start(
                endpointA, TransportKind.XRAY_REALITY, sessionId = 901L,
                onSuperseded = { throw CancellationException("scope cancelled") },
                onSupersededFailed = { failures += it },
            )
            fail("CancellationException must propagate")
        } catch (e: CancellationException) {
            assertEquals("scope cancelled", e.message)
        }

        assertTrue(failures.isEmpty()) // cancellation is not a publishing failure
        assertEquals(1, rt.startLoopCallCount) // no new core
        assertEquals(1, rt.stopLoopCallCount) // the old core was stopped before the callback
        assertFalse(c.stopSession().outcome.didTeardown) // the mutex was released; nothing is left running
    }

    // 6. Failure of the new START, including the B33 branch.
    @Test
    fun `new START fails with RemoteUnconfirmed - old session reported stopped, nothing runs, nobody can stop anything`() = runTest {
        val rt = FlakyRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        c.go(900L, log)
        rt.failMeasure = true

        val outcome = c.go(901L, log)

        assertTrue("unexpected $outcome", outcome is XrayCoreStartOutcome.RemoteUnconfirmed)
        assertEquals(listOf("start(900)=Started", "Stopped(900)", "start(901)=RemoteUnconfirmed"), log)
        assertFalse(rt.inner.isRunning)
        assertEquals(2, rt.inner.stopLoopCallCount) // supersede stop + the unconfirmed attempt's own teardown
        assertFalse(c.stopSession(expectedSessionId = 901L).outcome.didTeardown)
        assertFalse(c.stopSession(expectedSessionId = 900L).outcome.didTeardown)
    }

    // 7. Duplicate START/STOP and a late STOP of the older session.
    @Test
    fun `duplicate START 901 during the held exchange and repeated STOPs change nothing twice`() = runTest {
        val rt = FakeXrayCoreRuntime(); val repo = GateRepo(validProfile); val log = mutableListOf<String>()
        val c = coordinatorFor(rt, repo, this)
        c.go(900L, log)
        val gate = CompletableDeferred<Unit>(); repo.gate = gate
        val first = async { c.go(901L, log) }
        runCurrent()
        val duplicate = async { c.go(901L, log) }
        runCurrent()

        gate.complete(Unit); runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, first.await())
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, duplicate.await())
        assertEquals(listOf("start(900)=Started", "Stopped(900)", "start(901)=Started", "start(901)=AlreadyRunning"), log) // one Stopped(900)
        assertEquals(2, rt.startLoopCallCount); assertEquals(1, rt.stopLoopCallCount)
        assertFalse(c.stopSession(expectedSessionId = 900L).outcome.didTeardown) // late STOP of the older session
        assertTrue(rt.isRunning)
        assertEquals(901L, c.stopSession(expectedSessionId = 901L).sessionId)
        val again = c.stopSession(expectedSessionId = 901L)
        assertFalse(again.outcome.didTeardown); assertNull(again.otherRunningSessionId)
        assertEquals(2, rt.stopLoopCallCount)
    }
}
