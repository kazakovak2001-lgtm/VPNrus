package net.pocvpn.b46harness

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B46-2P - PRE-MERGE HARDENING CORRECTION (round 4) regression tests:
 * unknown/non-allowlisted child output must never be logged, and a safe
 * marker embedded in or followed by arbitrary text must NOT be treated as
 * safe (round 3's `containsMatchIn`-based filter allowed exactly that -
 * see [B46ChildLogFilter]'s own doc for the real example that motivated
 * this). Proven here as a pure decision function so no `android.util.Log`
 * mock/Robolectric is needed.
 */
class B46ChildLogFilterTest {

    private val configLoaded = "loaded config-file: server=1.2.3.4:34443 sni=example.test insecure=true " +
        "socksListen=127.0.0.1:41080 protectPath=/data/user/0/net.pocvpn.b46harness/files/b46-hysteria/b46-protect.sock " +
        "authSet=true obfsSet=false"
    private val fdProtect = "FD_PROTECT_SCM_RIGHTS: protect() succeeded via /data/.../b46-protect.sock for fd=3"

    private fun timestamped(line: String) = "2026/09/20 05:37:45 $line"

    // 1. valid timestamped connected event passes
    @Test
    fun `timestamped connected event passes`() {
        val line = timestamped("connected: udpEnabled=true tx=0")
        assertEquals(line, B46ChildLogFilter.safeLogLine(line))
    }

    // 2. valid non-timestamped connected event passes (intentionally supported - optional prefix)
    @Test
    fun `non-timestamped connected event passes`() {
        val line = "connected: udpEnabled=false tx=1234"
        assertEquals(line, B46ChildLogFilter.safeLogLine(line))
    }

    // 3. valid SOCKS listener event passes
    @Test
    fun `SOCKS5_LISTENING event passes, timestamped and not`() {
        val a = timestamped("SOCKS5_LISTENING addr=127.0.0.1:41080")
        val b = "SOCKS5_LISTENING addr=0.0.0.0:0"
        assertEquals(a, B46ChildLogFilter.safeLogLine(a))
        assertEquals(b, B46ChildLogFilter.safeLogLine(b))
    }

    // 4. valid shutdown events pass
    @Test
    fun `shutdown events pass, timestamped and not`() {
        assertEquals(timestamped("shutting down"), B46ChildLogFilter.safeLogLine(timestamped("shutting down")))
        assertEquals("shutting down", B46ChildLogFilter.safeLogLine("shutting down"))
        assertEquals(timestamped("shutdown timed out"), B46ChildLogFilter.safeLogLine(timestamped("shutdown timed out")))
        assertEquals("shutdown timed out", B46ChildLogFilter.safeLogLine("shutdown timed out"))
    }

    // 5. valid redacted config-loaded event passes (the EXACT redactedSummary() shape - all 7 fields)
    @Test
    fun `full redacted config-loaded event passes`() {
        assertEquals(timestamped(configLoaded), B46ChildLogFilter.safeLogLine(timestamped(configLoaded)))
        assertEquals(configLoaded, B46ChildLogFilter.safeLogLine(configLoaded))
    }

    // 6. valid FD-protect event passes (all three real emitted shapes)
    @Test
    fun `FD_PROTECT event shapes pass`() {
        assertEquals(timestamped(fdProtect), B46ChildLogFilter.safeLogLine(timestamped(fdProtect)))
        assertEquals("FD_PROTECT_STUB: called on fd=3", B46ChildLogFilter.safeLogLine("FD_PROTECT_STUB: called on fd=3"))
        assertEquals("FD_PROTECT_MARK: set SO_MARK=0x2333 on fd=5", B46ChildLogFilter.safeLogLine("FD_PROTECT_MARK: set SO_MARK=0x2333 on fd=5"))
    }

    // 7. "connected ... auth=secret" is rejected
    @Test
    fun `connected event with appended secret-shaped text is rejected, not logged`() {
        assertNull(B46ChildLogFilter.safeLogLine(timestamped("connected: udpEnabled=true tx=0 auth=DO_NOT_LOG")))
        assertNull(B46ChildLogFilter.safeLogLine("connected: udpEnabled=true tx=0 auth=DO_NOT_LOG"))
    }

    // 8. "SOCKS5_LISTENING ... secret=..." is rejected
    @Test
    fun `SOCKS5_LISTENING event with appended secret-shaped text is rejected`() {
        assertNull(B46ChildLogFilter.safeLogLine("SOCKS5_LISTENING addr=127.0.0.1:41080 secret=oops"))
    }

    // 9. safe marker embedded in arbitrary text is rejected
    @Test
    fun `safe marker embedded in the middle of arbitrary text is rejected`() {
        assertNull(B46ChildLogFilter.safeLogLine("prefix garbage connected: udpEnabled=true tx=0 suffix garbage"))
        assertNull(B46ChildLogFilter.safeLogLine("some text containing FD_PROTECT_SCM_RIGHTS somewhere in the middle"))
    }

    // 10. safe marker with arbitrary trailing text is rejected
    @Test
    fun `safe marker followed by arbitrary trailing text is rejected - the real motivating example`() {
        // This is the EXACT shape that motivated round 4: round 3's
        // containsMatchIn-based filter would have logged this line in
        // full, including the trailing auth value.
        assertNull(B46ChildLogFilter.safeLogLine(timestamped("connected: udpEnabled=true tx=0 auth=DO_NOT_LOG")))
        assertNull(B46ChildLogFilter.safeLogLine("shutting down and also dumping auth=super-secret-value here"))
    }

    // 11. completely unknown line is rejected
    @Test
    fun `unknown, non-allowlisted line is never returned as safe to log`() {
        assertNull(B46ChildLogFilter.safeLogLine(timestamped("hysteria client construction/handshake failed: protect fd: protect() rejected: ack=0xff")))
        assertNull(B46ChildLogFilter.safeLogLine("some arbitrary stderr text that happens to be printed"))
        assertNull(B46ChildLogFilter.safeLogLine("auth=super-secret-value-should-never-be-logged"))
        assertNull(B46ChildLogFilter.safeLogLine(""))
    }

    @Test
    fun `a truncated config-loaded line missing required fields is rejected, not partially accepted`() {
        // Guards against a regex that only checked a PREFIX of the real
        // redactedSummary() shape (an earlier, wrong test fixture used
        // exactly this truncated form before round 4).
        assertNull(B46ChildLogFilter.safeLogLine("loaded config-file: server=1.2.3.4:34443 authSet=true"))
    }
}
