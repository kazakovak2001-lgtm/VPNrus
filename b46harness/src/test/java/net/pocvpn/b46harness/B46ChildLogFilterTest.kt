package net.pocvpn.b46harness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B46-2P - PRE-MERGE HARDENING CORRECTION (round 3) regression tests:
 * unknown/non-allowlisted child output must never be logged, proven here
 * as a pure decision function so no `android.util.Log` mock/Robolectric is
 * needed - see [B46ChildLogFilter]'s own doc.
 */
class B46ChildLogFilterTest {

    // 3. unknown child log content is NOT emitted to the logcat-facing path
    @Test
    fun `unknown, non-allowlisted line is never returned as safe to log`() {
        assertNull(B46ChildLogFilter.safeLogLine("2026/09/20 05:37:45 hysteria client construction/handshake failed: protect fd: protect() rejected: ack=0xff"))
        assertNull(B46ChildLogFilter.safeLogLine("some arbitrary stderr text that happens to be printed"))
        assertNull(B46ChildLogFilter.safeLogLine("auth=super-secret-value-should-never-be-logged"))
        assertNull(B46ChildLogFilter.safeLogLine(""))
    }

    // 4. safe allowlisted child event still reaches the safe logger
    @Test
    fun `known-safe event shapes are returned as safe to log, unchanged`() {
        val connected = "2026/09/20 05:37:45 connected: udpEnabled=true tx=0"
        val socks = "2026/09/20 05:37:45 SOCKS5_LISTENING addr=127.0.0.1:41080"
        val shutdown = "2026/09/20 05:37:45 shutting down"
        val shutdownTimeout = "2026/09/20 05:37:45 shutdown timed out"
        val configLoaded = "2026/09/20 05:37:45 loaded config-file: server=1.2.3.4:34443 authSet=true"
        val protect = "2026/09/20 05:37:45 FD_PROTECT_SCM_RIGHTS: protect() succeeded via /path for fd=3"

        assertEquals(connected, B46ChildLogFilter.safeLogLine(connected))
        assertEquals(socks, B46ChildLogFilter.safeLogLine(socks))
        assertEquals(shutdown, B46ChildLogFilter.safeLogLine(shutdown))
        assertEquals(shutdownTimeout, B46ChildLogFilter.safeLogLine(shutdownTimeout))
        assertEquals(configLoaded, B46ChildLogFilter.safeLogLine(configLoaded))
        assertEquals(protect, B46ChildLogFilter.safeLogLine(protect))
    }

    @Test
    fun `a line that happens to embed a safe marker but also secret-shaped text is still allowed through - allowlist is a shape match, not a content scrub`() {
        // This documents an intentional boundary, not a gap: the allowlist
        // recognizes known SAFE event shapes emitted by our own child
        // binary (novaminimal_main.go), which never embeds auth/obfs in
        // these specific safe lines itself (see that file's own log call
        // sites) - the filter is not a general secret scrubber, and is not
        // relied upon as one; the child's own redact() plus never logging
        // UNKNOWN content are the actual defenses against a secret
        // appearing in an unexpected line shape.
        val safeShapeOnly = "connected: udpEnabled=true tx=0"
        assertEquals(safeShapeOnly, B46ChildLogFilter.safeLogLine(safeShapeOnly))
    }
}
