@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 3D contract (temporary copy only): the transport keeps ONE activeSessionId, so a START with a
 * NEWER session id on a running core means the old session has no owner left. The coordinator
 * replaces the core under one lock hold (old session reported through onSuperseded, then the new
 * session starts for real). Same/older/unknown ids stay AlreadyRunning (duplicate or stale START).
 * Invariant: a core runs only for the session in [NovaXrayServiceLifecycleCoordinator]'s running id.
 */
class NovaXrayServiceLifecycleAlreadyRunningTest {

    private val validProfile = XrayProfile(
        server = "152.70.43.1", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
        fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    private class Repo(private val profile: XrayProfile?) : XrayProfileRepository {
        override suspend fun getProfileOrNull(): XrayProfile? = profile
        override suspend fun saveProfile(profile: XrayProfile) {}
        override suspend fun clearProfile() {}
    }

    /** Starts fine until [failStarts] is set; isRunning/stopLoop are the inner fake's. */
    private class FlakyRuntime(val inner: FakeXrayCoreRuntime = FakeXrayCoreRuntime()) : XrayCoreRuntime by inner {
        var failStarts = false
        override fun startLoop(configContent: String, tunFd: Int) {
            if (failStarts) throw IllegalStateException("core refused to start")
            inner.startLoop(configContent, tunFd)
        }
    }

    private val endpointA = EndpointId("gateway-a")

    private fun coordinatorFor(runtime: XrayCoreRuntime, scope: kotlinx.coroutines.CoroutineScope) =
        NovaXrayServiceLifecycleCoordinator {
            XrayCoreController(
                repository = Repo(validProfile),
                coreRuntime = runtime,
                novaPackageId = "net.pocvpn.client.test",
                ensureCoreEnvInitialized = {},
                establishTun = { 42 },
                closeTun = {},
                probeScope = scope,
            )
        }

    private suspend fun NovaXrayServiceLifecycleCoordinator.startA(id: Long?, superseded: MutableList<Long>) =
        start(endpointA, TransportKind.XRAY_REALITY, sessionId = id, onSuperseded = { superseded += it })

    // 1. N runs, START(N+1) on the same endpoint.
    @Test
    fun `START of a newer session replaces the running core and reports the old session first`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        assertEquals(XrayCoreStartOutcome.Started, c.startA(900L, superseded))

        val outcome = c.startA(901L, superseded)

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(listOf(900L), superseded)
        assertEquals(1, rt.stopLoopCallCount)
        assertEquals(2, rt.startLoopCallCount)
        assertTrue(rt.isRunning)
    }

    // 2. STOP(N+1) cannot leave a core without an owner.
    @Test
    fun `STOP of the new session after the replacement stops the core, a repeat is a no-op`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)
        c.startA(901L, superseded)

        val stop = c.stopSession(expectedSessionId = 901L)

        assertTrue(stop.outcome.didTeardown)
        assertEquals(901L, stop.sessionId)
        assertFalse(rt.isRunning)
        val again = c.stopSession(expectedSessionId = 901L)
        assertFalse(again.outcome.didTeardown)
        assertEquals(null, again.otherRunningSessionId)
    }

    // 3. A late STOP(N) cannot stop the newer, really running session.
    @Test
    fun `a late STOP of the superseded session is refused and the new core keeps running`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)
        c.startA(901L, superseded)

        val late = c.stopSession(expectedSessionId = 900L)

        assertFalse(late.outcome.didTeardown)
        assertEquals(901L, late.otherRunningSessionId)
        assertTrue(rt.isRunning)
        assertEquals(1, rt.stopLoopCallCount) // only the replacement stopped a core
    }

    // 4. Published results match the real process state - also when the replacement fails.
    @Test
    fun `a failed replacement leaves nothing running, nothing owned, and the old session reported stopped`() = runTest {
        val rt = FlakyRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)
        rt.failStarts = true

        val outcome = c.startA(901L, superseded)

        assertTrue("unexpected $outcome", outcome is XrayCoreStartOutcome.CoreStartFailed)
        assertEquals(listOf(900L), superseded) // the old core really was stopped
        assertFalse(rt.inner.isRunning)
        // Neither session can end anything now, and an untagged stop is a harmless no-op.
        assertFalse(c.stopSession(expectedSessionId = 901L).outcome.didTeardown)
        assertFalse(c.stopSession(expectedSessionId = 900L).outcome.didTeardown)
        assertFalse(c.stopSession().outcome.didTeardown)
    }

    // 5. Determinism: duplicates, stale and unknown ids never replace; rapid reconnects end on the last id.
    @Test
    fun `duplicate, older and unknown-id STARTs stay AlreadyRunning and never touch the core`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(902L, superseded)

        assertEquals(XrayCoreStartOutcome.AlreadyRunning, c.startA(902L, superseded)) // duplicate
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, c.startA(900L, superseded)) // stale
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, c.startA(null, superseded)) // unknown id

        assertTrue(superseded.isEmpty())
        assertEquals(1, rt.startLoopCallCount)
        assertEquals(0, rt.stopLoopCallCount)
        assertEquals(902L, c.stopSession().sessionId)
    }

    @Test
    fun `rapid reconnect START 900, 901, 902 queued together ends on 902 with both older cores reported`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()

        val a = async { c.startA(900L, superseded) }
        val b = async { c.startA(901L, superseded) }
        val d = async { c.startA(902L, superseded) }
        runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, a.await())
        assertEquals(XrayCoreStartOutcome.Started, b.await())
        assertEquals(XrayCoreStartOutcome.Started, d.await())
        assertEquals(listOf(900L, 901L), superseded)
        assertEquals(3, rt.startLoopCallCount)
        assertEquals(2, rt.stopLoopCallCount)
        assertEquals(902L, c.stopSession(expectedSessionId = 902L).sessionId)
        assertFalse(rt.isRunning)
    }

    @Test
    fun `STOP(900) then START(901) starts fresh without a superseded report`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)

        assertEquals(900L, c.stopSession(expectedSessionId = 900L).sessionId)
        assertEquals(XrayCoreStartOutcome.Started, c.startA(901L, superseded))

        assertTrue(superseded.isEmpty())
        assertEquals(901L, c.stopSession(expectedSessionId = 901L).sessionId)
    }

    @Test
    fun `START(901) then STOP(900) - the late stop is refused`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)
        c.startA(901L, superseded)

        assertFalse(c.stopSession(expectedSessionId = 900L).outcome.didTeardown)
        assertEquals(901L, c.stopSession(expectedSessionId = 901L).sessionId)
        assertFalse(rt.isRunning)
    }

    @Test
    fun `an untagged stop still ends whatever runs after a replacement`() = runTest {
        val rt = FakeXrayCoreRuntime()
        val c = coordinatorFor(rt, this)
        val superseded = mutableListOf<Long>()
        c.startA(900L, superseded)
        c.startA(901L, superseded)

        assertEquals(901L, c.stopSession().sessionId)
        assertFalse(rt.isRunning)
    }
}
