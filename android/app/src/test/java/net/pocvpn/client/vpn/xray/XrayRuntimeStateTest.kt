package net.pocvpn.client.vpn.xray

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B8I7 - proves the in-process signal itself: publish/replay semantics and
 * that a fresh subscriber sees the CURRENT value (never silently missing an
 * event that raced ahead of subscription). Session-filtering (the actual
 * "stale event rejected" behavior) is proven in XrayTransportStateForTest,
 * against the exact function VlessRealityTransport's own collector uses.
 * XrayRuntimeState is a process-wide singleton (matches AlwaysOnVpnState's
 * own shape) - these tests only ever assert the value immediately AFTER a
 * publish() they themselves performed, never an assumed "starting" value,
 * since other tests in the same JVM may have already published to it.
 */
class XrayRuntimeStateTest {

    @Test
    fun `watchdog publisher adds a typed fact only for XHTTP`() {
        XrayRuntimeState.publishRelayHealthLost(1L, TransportKind.XRAY_XHTTP)
        assertEquals(
            XrayRuntimeEvent.Failed(1L, "relay data-plane health check failed", TransportFailureKind.RELAY_DATA_PLANE_LOST),
            XrayRuntimeState.events.value,
        )
        for (kind in listOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP)) {
            XrayRuntimeState.publishRelayHealthLost(2L, kind)
            assertEquals(XrayRuntimeEvent.Failed(2L, "relay data-plane health check failed"), XrayRuntimeState.events.value)
        }
    }

    @Test
    fun `publish replaces the current value and a new subscriber immediately sees it`() {
        XrayRuntimeState.publish(XrayRuntimeEvent.Started(sessionId = 111L))
        assertEquals(XrayRuntimeEvent.Started(111L), XrayRuntimeState.events.value)

        XrayRuntimeState.publish(XrayRuntimeEvent.Failed(sessionId = 222L, reason = "no Xray profile configured"))
        assertEquals(XrayRuntimeEvent.Failed(222L, "no Xray profile configured"), XrayRuntimeState.events.value)

        XrayRuntimeState.publish(XrayRuntimeEvent.Stopped(sessionId = 222L))
        assertEquals(XrayRuntimeEvent.Stopped(222L), XrayRuntimeState.events.value)
    }
}
