package net.pocvpn.client.vpn.xray

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B21-fix - proves [XrayCoreDiagnostics] never keeps secret-shaped content
 * and never grows unbounded, independent of any Android/native dependency.
 */
class XrayCoreDiagnosticsTest {

    @After
    fun tearDown() {
        XrayCoreDiagnostics.clear()
    }

    @Test
    fun `a uuid-shaped token in a status line is redacted`() {
        XrayCoreDiagnostics.record("status", "failed to dial user 3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f")

        val message = XrayCoreDiagnostics.events.value.single().message
        assertFalse(message.contains("3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f"))
        assertTrue(message.contains("[redacted]"))
    }

    @Test
    fun `a long base64-shaped token (reality key shape) is redacted`() {
        val keyShaped = "A".repeat(43)

        XrayCoreDiagnostics.record("status", "REALITY: Choosing $keyShaped")

        assertFalse(XrayCoreDiagnostics.events.value.single().message.contains(keyShaped))
    }

    @Test
    fun `ordinary non-secret status text is preserved`() {
        XrayCoreDiagnostics.record("status", "failed to open quic connection")

        assertEquals("failed to open quic connection", XrayCoreDiagnostics.events.value.single().message)
    }

    @Test
    fun `a null message records as an empty string, never a crash`() {
        XrayCoreDiagnostics.record("startup", null)

        assertEquals("", XrayCoreDiagnostics.events.value.single().message)
    }

    @Test
    fun `the event buffer is bounded and keeps only the most recent entries`() {
        repeat(80) { i -> XrayCoreDiagnostics.record("status", "event $i") }

        val events = XrayCoreDiagnostics.events.value
        assertEquals(50, events.size)
        assertEquals("event 79", events.last().message)
        assertEquals("event 30", events.first().message)
    }

    @Test
    fun `an overlong message is truncated`() {
        XrayCoreDiagnostics.record("status", "x".repeat(500))

        assertTrue(XrayCoreDiagnostics.events.value.single().message.length <= 200)
    }
}
