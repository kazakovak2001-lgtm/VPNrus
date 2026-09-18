package net.pocvpn.client.debug.b46hysteria

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2A/B46-2B - PREPARATION ONLY. Unit tests for the pure
 * [B46HysteriaSpikeTransitions] state machine - no real process, TUN, or
 * Unix-domain socket involved. See B46HysteriaSpikeState.kt's own header
 * for why this exists without a real runtime/service class yet.
 */
class B46HysteriaSpikeStateTest {

    @Test
    fun `initial status is IDLE`() {
        assertEquals(B46HysteriaSpikePhase.IDLE, B46HysteriaSpikeStatus.IDLE.phase)
    }

    @Test
    fun `canStart is true from IDLE and STOPPED only`() {
        assertTrue(B46HysteriaSpikeTransitions.canStart(B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.IDLE)))
        assertTrue(B46HysteriaSpikeTransitions.canStart(B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.STOPPED)))
    }

    @Test
    fun `canStart is false from ERROR - restart must go through explicit cleanup first`() {
        // ERROR only records that something went wrong, never that cleanup finished - a runtime/
        // process/resource may still be live. Restarting directly from ERROR would risk starting
        // a second session on top of one that was never confirmed torn down.
        assertFalse(B46HysteriaSpikeTransitions.canStart(B46HysteriaSpikeStatus(phase = B46HysteriaSpikePhase.ERROR)))
    }

    @Test
    fun `required recovery path from ERROR is STOPPING then STOPPED then STARTING`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 42)
        status = B46HysteriaSpikeTransitions.failed(status, B46HysteriaSpikeError.RuntimeSpawnFailed("boom"))
        assertEquals(B46HysteriaSpikePhase.ERROR, status.phase)
        assertFalse(B46HysteriaSpikeTransitions.canStart(status))

        // ERROR must still be stoppable (cleanup is how you get OUT of ERROR).
        assertTrue(B46HysteriaSpikeTransitions.canStop(status))
        status = B46HysteriaSpikeTransitions.stopping(status)
        assertEquals(B46HysteriaSpikePhase.STOPPING, status.phase)
        assertFalse(B46HysteriaSpikeTransitions.canStart(status))

        status = B46HysteriaSpikeTransitions.stopped()
        assertEquals(B46HysteriaSpikePhase.STOPPED, status.phase)
        assertTrue(B46HysteriaSpikeTransitions.canStart(status))

        status = B46HysteriaSpikeTransitions.starting()
        assertEquals(B46HysteriaSpikePhase.STARTING, status.phase)
    }

    @Test
    fun `canStart is false while already running`() {
        for (phase in listOf(
            B46HysteriaSpikePhase.STARTING,
            B46HysteriaSpikePhase.TUN_ESTABLISHED,
            B46HysteriaSpikePhase.TUN_BRIDGE_READY,
            B46HysteriaSpikePhase.RUNTIME_STARTED,
            B46HysteriaSpikePhase.FD_CONTROL_READY,
            B46HysteriaSpikePhase.DATA_PLANE_READY,
            B46HysteriaSpikePhase.STOPPING,
        )) {
            assertFalse("expected canStart=false for $phase", B46HysteriaSpikeTransitions.canStart(B46HysteriaSpikeStatus(phase = phase)))
        }
    }

    @Test
    fun `full happy path progresses through every phase in order`() {
        var status = B46HysteriaSpikeTransitions.starting()
        assertEquals(B46HysteriaSpikePhase.STARTING, status.phase)

        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        assertEquals(B46HysteriaSpikePhase.TUN_ESTABLISHED, status.phase)

        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        assertEquals(B46HysteriaSpikePhase.TUN_BRIDGE_READY, status.phase)

        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 1234)
        assertEquals(B46HysteriaSpikePhase.RUNTIME_STARTED, status.phase)
        assertEquals(1234, status.runtimePid)

        status = B46HysteriaSpikeTransitions.fdControlReady(status)
        assertEquals(B46HysteriaSpikePhase.FD_CONTROL_READY, status.phase)

        status = B46HysteriaSpikeTransitions.dataPlaneReady(status)
        assertEquals(B46HysteriaSpikePhase.DATA_PLANE_READY, status.phase)

        assertTrue(B46HysteriaSpikeTransitions.canStop(status))
        status = B46HysteriaSpikeTransitions.stopping(status)
        assertEquals(B46HysteriaSpikePhase.STOPPING, status.phase)

        status = B46HysteriaSpikeTransitions.stopped()
        // A completed stop reaches STOPPED, not IDLE - they are distinct phases (IDLE = never
        // started; STOPPED = ran and was cleanly torn down), and collapsing them would make
        // STOPPED unreachable via the normal stop path.
        assertEquals(B46HysteriaSpikeStatus.STOPPED, status)
        assertEquals(B46HysteriaSpikePhase.STOPPED, status.phase)
    }

    @Test
    fun `dataPlaneReady cannot be reached by skipping fdControlReady`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 1)
        try {
            B46HysteriaSpikeTransitions.dataPlaneReady(status)
            org.junit.Assert.fail("expected IllegalStateException skipping FD_CONTROL_READY")
        } catch (expected: IllegalStateException) {
            // expected: RUNTIME_STARTED alone (process running) is never sufficient for DATA_PLANE_READY.
        }
    }

    @Test
    fun `runtimeStarted cannot be reached by skipping tunBridgeReady`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        try {
            B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 1)
            org.junit.Assert.fail("expected IllegalStateException skipping TUN_BRIDGE_READY")
        } catch (expected: IllegalStateException) {
            // expected: TUN_ESTABLISHED alone (fd exists) is never sufficient to start the Hysteria2
            // process - the sing-tun-driven relay (B46-2B, Option A) must be live first, since the
            // process has nothing to talk to before the bridge is running.
        }
    }

    @Test
    fun `bridgeFailed clears to ERROR with typed BridgeFailed cause but does NOT clear runtimePid before Hysteria2 has started`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)

        status = B46HysteriaSpikeTransitions.bridgeFailed(status, reason = "stack panic")

        assertEquals(B46HysteriaSpikePhase.ERROR, status.phase)
        assertEquals(null, status.runtimePid) // never started in this path - nothing to preserve
        assertTrue(status.lastError is B46HysteriaSpikeError.BridgeFailed)
    }

    @Test
    fun `bridgeFailed does NOT falsely clear a still-owned Hysteria runtimePid - a bridge failure never proves the runtime process exited`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 4242)
        assertEquals(4242, status.runtimePid)

        status = B46HysteriaSpikeTransitions.bridgeFailed(status, reason = "stack panic while Hysteria2 was running")

        assertEquals(B46HysteriaSpikePhase.ERROR, status.phase)
        // The bridge and the Hysteria2 runtime are separate ownership domains (B46-2B review fix) -
        // a bridge failure must never claim the still-running runtime process is no longer owned/tracked.
        assertEquals(4242, status.runtimePid)
        assertTrue(status.lastError is B46HysteriaSpikeError.BridgeFailed)
    }

    @Test
    fun `runtimeExitedUnexpectedly is the ONLY transition that clears runtimePid - proven by contrast with bridgeFailed`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 555)

        val afterBridgeFailure = B46HysteriaSpikeTransitions.bridgeFailed(status, reason = "worker crash")
        assertEquals(555, afterBridgeFailure.runtimePid) // preserved

        val afterRuntimeExit = B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly(status, exitCode = 9)
        assertEquals(null, afterRuntimeExit.runtimePid) // cleared - evidence the process itself exited
    }

    @Test
    fun `stop is idempotent - canStop is false once STOPPED or IDLE`() {
        assertFalse(B46HysteriaSpikeTransitions.canStop(B46HysteriaSpikeStatus.IDLE))
        assertFalse(B46HysteriaSpikeTransitions.canStop(B46HysteriaSpikeStatus.STOPPED))
    }

    @Test
    fun `runtimeExitedUnexpectedly always clears to ERROR with exit code recorded`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 77)

        status = B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly(status, exitCode = 137)

        assertEquals(B46HysteriaSpikePhase.ERROR, status.phase)
        assertEquals(137, status.exitCode)
        assertTrue(status.lastError is B46HysteriaSpikeError.RuntimeExitedUnexpectedly)
    }

    @Test
    fun `runtimeExitedUnexpectedly clears runtimePid - a terminated process is never claimed as owned`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 999)
        assertEquals(999, status.runtimePid)

        status = B46HysteriaSpikeTransitions.runtimeExitedUnexpectedly(status, exitCode = 1)

        // The pid is cleared - the process is KNOWN dead, so ERROR must never claim ownership of it.
        assertEquals(null, status.runtimePid)
        // exitCode remains as separate, purely diagnostic evidence of how the run ended.
        assertEquals(1, status.exitCode)
    }

    @Test
    fun `fdControl request counters accumulate without resetting other fields`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        status = B46HysteriaSpikeTransitions.tunBridgeReady(status)
        status = B46HysteriaSpikeTransitions.runtimeStarted(status, pid = 5)
        status = B46HysteriaSpikeTransitions.fdControlReady(status)

        status = B46HysteriaSpikeTransitions.onFdControlRequestHandled(status, succeeded = true)
        status = B46HysteriaSpikeTransitions.onFdControlRequestHandled(status, succeeded = false)

        assertEquals(2, status.fdControlRequestCount)
        assertEquals(1, status.fdControlFailureCount)
        assertEquals(5, status.runtimePid) // untouched by the counter update
        assertEquals(B46HysteriaSpikePhase.FD_CONTROL_READY, status.phase) // untouched by the counter update
    }

    @Test
    fun `failed preserves prior status fields and records the typed error`() {
        var status = B46HysteriaSpikeTransitions.starting()
        status = B46HysteriaSpikeTransitions.tunEstablished(status)
        val error = B46HysteriaSpikeError.RuntimeSpawnFailed("binary missing")

        status = B46HysteriaSpikeTransitions.failed(status, error)

        assertEquals(B46HysteriaSpikePhase.ERROR, status.phase)
        assertEquals(error, status.lastError)
    }
}
