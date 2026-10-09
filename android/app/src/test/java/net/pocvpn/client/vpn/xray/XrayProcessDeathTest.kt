package net.pocvpn.client.vpn.xray

import net.pocvpn.client.vpn.xray.XrayProcessBridge.DeathAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A death of `:xray` nobody asked for is reported Failed at once (Android
 * has already removed the VPN interface - the old unconditional 2 s grace
 * showed Protected over a missing tunnel, ~2.3 s measured on the OPPO).
 * Only a stop the main process requested keeps the grace, and the main
 * process mirror accepts at most one terminal event per session.
 */
class XrayProcessDeathTest {

    private fun started(id: Long) = XrayRuntimeEvent.Started(id)
    private fun failed(id: Long, reason: String = "boom") = XrayRuntimeEvent.Failed(id, reason)
    private fun stopped(id: Long) = XrayRuntimeEvent.Stopped(id)

    // --- deathAction: session lifecycle ----------------------------------------------

    @Test
    fun `an unexpected death of a Started session fails at once`() {
        assertEquals(DeathAction.FAIL_NOW, XrayProcessBridge.deathAction(10L, started(10L), stopRequestedSession = null))
    }

    @Test
    fun `a death after the main process asked this session to stop keeps the grace`() {
        assertEquals(DeathAction.AWAIT_GRACE, XrayProcessBridge.deathAction(10L, started(10L), stopRequestedSession = 10L))
    }

    @Test
    fun `a stop requested for an older session never shields a reconnected newer one`() {
        // Reconnect: session 10 was stopped by us, session 11 started, then 11 crashes.
        assertEquals(DeathAction.FAIL_NOW, XrayProcessBridge.deathAction(11L, started(11L), stopRequestedSession = 10L))
    }

    @Test
    fun `a session that already ended or was superseded is ignored`() {
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(10L, stopped(10L), stopRequestedSession = null))
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(10L, failed(10L), stopRequestedSession = null))
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(10L, started(11L), stopRequestedSession = null))
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(10L, null, stopRequestedSession = null))
    }

    @Test
    fun `the service's own Failed arriving before the death notice means no second Failed`() {
        // Stopped/Failed race, service side first: the mirror is already terminal.
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(10L, failed(10L, "relay data-plane health check failed"), stopRequestedSession = null))
    }

    // --- acceptInMain: duplicate terminal events -------------------------------------

    @Test
    fun `a second terminal event for the same session is dropped`() {
        assertFalse(XrayProcessBridge.acceptInMain(failed(10L), stopped(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(stopped(10L), failed(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(failed(10L, "xray process died"), failed(10L, "late service reason")))
    }

    @Test
    fun `terminal events of a running or different session still pass`() {
        assertTrue(XrayProcessBridge.acceptInMain(started(10L), failed(10L)))
        assertTrue(XrayProcessBridge.acceptInMain(started(10L), stopped(10L)))
        assertTrue(XrayProcessBridge.acceptInMain(failed(10L), failed(11L)))
        assertTrue(XrayProcessBridge.acceptInMain(null, failed(10L)))
    }

    @Test
    fun `a new Started always passes, even right after a terminal event`() {
        assertTrue(XrayProcessBridge.acceptInMain(failed(10L), started(11L)))
        assertTrue(XrayProcessBridge.acceptInMain(stopped(10L), started(11L)))
    }

    // --- publishInMain: the mirror the transports observe ----------------------------

    @Test
    fun `death-time Failed then the service's late Stopped leaves the session Failed`() {
        val id = 9_000_000_001L
        XrayRuntimeState.publish(started(id))

        assertTrue(XrayProcessBridge.publishInMain(failed(id, "xray process died")))
        assertFalse(XrayProcessBridge.publishInMain(stopped(id)))

        assertEquals(failed(id, "xray process died"), XrayRuntimeState.events.value)
    }

    @Test
    fun `an expected stop delivers Stopped, and a late death-time Failed cannot override it`() {
        val id = 9_000_000_002L
        XrayRuntimeState.publish(started(id))
        XrayProcessBridge.noteStopRequested(id)

        // The grace exists for exactly this: Stopped reaches the mirror ...
        assertTrue(XrayProcessBridge.publishInMain(stopped(id)))
        // ... and the post-grace check then finds nothing to fail.
        assertEquals(DeathAction.IGNORE, XrayProcessBridge.deathAction(id, XrayRuntimeState.events.value, XrayProcessBridge.stopRequestedSession))
        assertFalse(XrayProcessBridge.publishInMain(failed(id, "xray process died")))
        assertEquals(stopped(id), XrayRuntimeState.events.value)
    }

    @Test
    fun `noteStopRequested only marks the given session`() {
        XrayProcessBridge.noteStopRequested(9_000_000_003L)

        assertEquals(9_000_000_003L, XrayProcessBridge.stopRequestedSession)
        assertEquals(DeathAction.FAIL_NOW, XrayProcessBridge.deathAction(9_000_000_004L, started(9_000_000_004L), XrayProcessBridge.stopRequestedSession))
    }
}
