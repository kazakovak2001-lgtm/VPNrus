package net.pocvpn.client.vpn.xray

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind
import net.pocvpn.client.vpn.xray.XrayProcessBridge.DeathOutcome
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The pure decisions behind the `:xray` death watch: a death nobody asked
 * for is Failed at once, a requested stop keeps the grace, the service's
 * own recorded terminal event for the SAME session wins (Stopped after a
 * system revoke, a typed relay-watchdog Failed), and the main mirror takes
 * nothing older than the session it shows.
 */
class XrayProcessDeathTest {

    private fun started(id: Long) = XrayRuntimeEvent.Started(id)
    private fun failed(id: Long, reason: String = "boom") = XrayRuntimeEvent.Failed(id, reason)
    private fun stopped(id: Long) = XrayRuntimeEvent.Stopped(id)
    private fun died(id: Long) = XrayRuntimeEvent.Failed(id, XrayProcessBridge.DIED_REASON)

    // --- onDeath -------------------------------------------------------------------

    @Test
    fun `an unexpected death with no record publishes a generic Failed at once`() {
        assertEquals(DeathOutcome.Publish(died(10L)), XrayProcessBridge.onDeath(10L, started(10L), null, null))
    }

    @Test
    fun `a requested stop with nothing recorded yet waits the grace`() {
        assertEquals(DeathOutcome.AwaitGrace, XrayProcessBridge.onDeath(10L, started(10L), stopRequestedSession = 10L, recorded = null))
    }

    @Test
    fun `a stop requested for an older session never shields a reconnected newer one`() {
        assertEquals(DeathOutcome.Publish(died(11L)), XrayProcessBridge.onDeath(11L, started(11L), stopRequestedSession = 10L, recorded = null))
    }

    @Test
    fun `the service's recorded Stopped (system VPN revoke) is published as Stopped, not Failed`() {
        assertEquals(DeathOutcome.Publish(stopped(10L)), XrayProcessBridge.onDeath(10L, started(10L), stopRequestedSession = null, recorded = stopped(10L)))
    }

    @Test
    fun `the relay watchdog's typed Failed keeps RELAY_DATA_PLANE_LOST`() {
        val relayLost = XrayRuntimeState.relayHealthLostEvent(10L, TransportKind.XRAY_XHTTP)
        val outcome = XrayProcessBridge.onDeath(10L, started(10L), stopRequestedSession = null, recorded = relayLost)
        assertEquals(DeathOutcome.Publish(relayLost), outcome)
        assertEquals(TransportFailureKind.RELAY_DATA_PLANE_LOST, ((outcome as DeathOutcome.Publish).event as XrayRuntimeEvent.Failed).failureKind)
    }

    @Test
    fun `a record left by an older session cannot turn a new session's crash into Stopped`() {
        assertEquals(DeathOutcome.Publish(died(11L)), XrayProcessBridge.onDeath(11L, started(11L), stopRequestedSession = null, recorded = stopped(10L)))
    }

    @Test
    fun `a session that already ended or was superseded is ignored, a null mirror too`() {
        assertEquals(DeathOutcome.Ignore, XrayProcessBridge.onDeath(10L, stopped(10L), null, null))
        assertEquals(DeathOutcome.Ignore, XrayProcessBridge.onDeath(10L, failed(10L), null, stopped(10L)))
        assertEquals(DeathOutcome.Ignore, XrayProcessBridge.onDeath(10L, started(11L), null, null))
        assertEquals(DeathOutcome.Ignore, XrayProcessBridge.onDeath(10L, null, null, null))
    }

    // --- afterGrace ----------------------------------------------------------------

    @Test
    fun `after the grace a still-Started session fails, preferring a record that appeared meanwhile`() {
        assertEquals(died(10L), XrayProcessBridge.afterGrace(10L, started(10L), null))
        assertEquals(stopped(10L), XrayProcessBridge.afterGrace(10L, started(10L), stopped(10L)))
        assertNull(XrayProcessBridge.afterGrace(10L, stopped(10L), null))
        assertNull(XrayProcessBridge.afterGrace(10L, started(11L), null))
    }

    // --- acceptInMain --------------------------------------------------------------

    @Test
    fun `a second terminal event for the same session is dropped`() {
        assertFalse(XrayProcessBridge.acceptInMain(failed(10L), stopped(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(stopped(10L), failed(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(died(10L), failed(10L, "late service reason")))
    }

    @Test
    fun `nothing from an older session reaches a mirror showing a newer one`() {
        assertFalse(XrayProcessBridge.acceptInMain(started(11L), stopped(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(started(11L), failed(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(started(11L), started(10L)))
        assertFalse(XrayProcessBridge.acceptInMain(failed(11L), stopped(10L)))
    }

    @Test
    fun `events of the shown or a newer session still pass`() {
        assertTrue(XrayProcessBridge.acceptInMain(started(10L), failed(10L)))
        assertTrue(XrayProcessBridge.acceptInMain(started(10L), stopped(10L)))
        assertTrue(XrayProcessBridge.acceptInMain(failed(10L), started(11L)))
        assertTrue(XrayProcessBridge.acceptInMain(started(10L), failed(11L)))
        assertTrue(XrayProcessBridge.acceptInMain(null, failed(10L)))
    }

    // --- stopSession: the transports' only stop path ------------------------------

    @Test
    fun `stopSession marks the session BEFORE ACTION_STOP is sent`() {
        val id = 9_200_000_000_000_001L
        var markedWhenSent: Long? = null
        var sends = 0

        XrayProcessBridge.stopSession(id) {
            sends++
            markedWhenSent = XrayProcessBridge.stopRequestedSession
        }

        assertEquals(1, sends)
        assertEquals(id, markedWhenSent)
    }

    @Test
    fun `stopSession without a session still sends the stop and marks nothing new`() {
        XrayProcessBridge.noteStopRequested(9_200_000_000_000_002L)
        var sends = 0

        XrayProcessBridge.stopSession(null) { sends++ }

        assertEquals(1, sends)
        assertEquals(9_200_000_000_000_002L, XrayProcessBridge.stopRequestedSession)
    }
}
