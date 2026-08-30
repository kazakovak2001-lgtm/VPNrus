package net.pocvpn.client.vpn

import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B8I7 - proves the exact event->TransportState mapping VlessRealityTransport's
 * own connect() collector uses, on the plain JVM (no Context needed): a
 * confirmed start becomes Connected, a runtime failure becomes Error, a real
 * stop becomes Disconnected, and - the crux of this slice - an event tagged
 * with a DIFFERENT (older or newer) session than the one currently being
 * observed is ignored entirely, never flipping state.
 */
class VlessRealityTransportStateTest {

    @Test
    fun `a Started event for the current session becomes Connected`() {
        assertEquals(TransportState.Connected, xrayTransportStateFor(XrayRuntimeEvent.Started(5L), sessionId = 5L))
    }

    @Test
    fun `a Failed event for the current session becomes Error carrying only the non-secret reason`() {
        val result = xrayTransportStateFor(XrayRuntimeEvent.Failed(5L, "no Xray profile configured"), sessionId = 5L)
        assertEquals(TransportState.Error("no Xray profile configured"), result)
    }

    @Test
    fun `a Stopped event for the current session becomes Disconnected`() {
        assertEquals(TransportState.Disconnected, xrayTransportStateFor(XrayRuntimeEvent.Stopped(5L), sessionId = 5L))
    }

    @Test
    fun `a null event (nothing published yet) is ignored`() {
        assertNull(xrayTransportStateFor(null, sessionId = 5L))
    }

    @Test
    fun `an event from an OLDER session is ignored - never marks a newer session Connected`() {
        // Session 4 already finished (or failed); session 5 is the CURRENT
        // attempt being observed. A late/stale Started(4) must not leak in.
        assertNull(xrayTransportStateFor(XrayRuntimeEvent.Started(4L), sessionId = 5L))
    }

    @Test
    fun `an event from a NEWER session is also ignored by an older observer`() {
        // The mirror case: an observer still watching session 5 must not
        // react to a session 6 event either (defense in depth - in practice
        // the OLD observer is cancelled before a new session starts).
        assertNull(xrayTransportStateFor(XrayRuntimeEvent.Started(6L), sessionId = 5L))
        assertFalse(xrayTransportStateFor(XrayRuntimeEvent.Started(6L), sessionId = 5L) == TransportState.Connected)
    }
}
