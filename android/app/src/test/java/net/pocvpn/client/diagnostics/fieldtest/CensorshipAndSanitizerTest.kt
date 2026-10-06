package net.pocvpn.client.diagnostics.fieldtest

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CensorshipAndSanitizerTest {

    private fun dns(ok: Boolean, vararg addrs: String) = DnsProbeResult("d", ok, addrs.toList(), 5, if (ok) null else "UnknownHostException")
    private fun tcp(ok: Boolean, error: String? = null) = TcpProbeResult("t", "1.2.3.4", 443, ok, 5, error)
    private fun tls(ok: Boolean, sni: String = "x") = TlsProbeResult(sni, ok, 5, if (ok) null else "SSLHandshakeException: Connection reset")
    private fun https(ok: Boolean, status: Int? = 200, stalledAt: Long? = null) =
        HttpProbeResult("h", "u", ok, status, 10, 5, stalledAt ?: 1000, stalledAt, ok, null)

    @Test fun `system DNS failing while DoH answers is DNS_BLOCKED`() =
        assertEquals(listOf("DNS_BLOCKED"), classifyTarget(dns(false), listOf("142.250.1.1"), tcp(true), tls(true), null, https(true), null))

    @Test fun `bogon answer is DNS tampering`() =
        assertTrue("DNS_TAMPERED_BOGON" in classifyTarget(dns(true, "127.0.0.1"), listOf("142.250.1.1"), tcp(true), tls(true), null, https(false, null), null))

    @Test fun `TCP timeout is IP_BLOCKED_DROP, reset is IP_BLOCKED_RESET`() {
        assertTrue("IP_BLOCKED_DROP" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(false, "SocketTimeoutException: connect timed out"), null, null, https(false, null), null))
        assertTrue("IP_BLOCKED_RESET" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(false, "ConnectException: Connection refused"), null, null, https(false, null), null))
    }

    @Test fun `real SNI fails but neutral SNI works is SNI_FILTERED`() =
        assertTrue("SNI_FILTERED" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(true), tls(false), tls(true, "www.example.org"), https(false, null), null))

    @Test fun `both SNIs failing is TLS_BLOCKED`() =
        assertTrue("TLS_BLOCKED" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(true), tls(false), tls(false), https(false, null), null))

    @Test fun `freeze after 16 KB is THROTTLED_STALL`() =
        assertTrue("THROTTLED_STALL" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(true), tls(true), null, https(false, 200, 16_384), null))

    @Test fun `ISP block page over plain HTTP is detected`() {
        assertTrue(looksLikeBlockPage("rutracker.org", "HTTP/1.1 302 Found", "http://warning.rt.ru/?id=1", ""))
        assertTrue(looksLikeBlockPage("x.com", "HTTP/1.1 200 OK", null, "<h1>Доступ ограничен</h1> по решению rkn.gov.ru"))
        assertFalse(looksLikeBlockPage("www.google.com", "HTTP/1.1 301 Moved", "https://www.google.com/", ""))
        val page = PlainHttpResult(true, "HTTP/1.1 302 Found", "http://warning.rt.ru/", 100, true, null)
        assertTrue("HTTP_BLOCK_PAGE" in classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(true), tls(true), null, https(true), page))
    }

    @Test fun `working target is OK`() =
        assertEquals(listOf("OK"), classifyTarget(dns(true, "1.2.3.4"), listOf("1.2.3.4"), tcp(true), tls(true), null, https(true), null))

    private fun result(domain: String, category: String, vararg verdicts: String, reachable: Boolean = "OK" in verdicts) =
        TargetCensorshipResult(
            CensorshipTarget(domain, category), dns(true, "1.2.3.4"), listOf("1.2.3.4"), null, null, null, null,
            if (reachable) https(true) else https(false, null), null, verdicts.toList(),
        )

    @Test fun `domestic up and foreign controls down suggests whitelist mode`() {
        val v = classifyNetwork(
            listOf(
                result("ya.ru", "domestic-control", "OK"),
                result("www.google.com", "foreign-control", "IP_BLOCKED_DROP"),
                result("telegram.org", "foreign-commonly-blocked", "SNI_FILTERED"),
            ),
            mapOf("8.8.8.8:53" to false), mapOf("cloudflare" to false),
        )
        assertTrue(v.any { it.startsWith("WHITELIST_MODE_SUSPECTED") })
        assertTrue("UDP53_TO_FOREIGN_RESOLVERS_BLOCKED" in v)
        assertTrue("DOH_BLOCKED" in v)
        assertTrue(v.any { it.startsWith("MECHANISMS") && "SNI_FILTERED" in it })
    }

    @Test fun `unreachable Nova host is called out`() {
        val v = classifyNetwork(listOf(result("control.aknova.pp.ua", "nova-infrastructure", "IP_BLOCKED_DROP")), emptyMap(), emptyMap())
        assertTrue(v.any { it.startsWith("NOVA_HOST_UNREACHABLE control.aknova.pp.ua") })
    }

    @Test fun `log sanitizer removes identities and secrets but keeps debug context`() {
        val line = "D/Xray: vless uuid=3f2a9c1e-1b2c-4d5e-8f90-1234567890ab key 3aG8tN3s9uF5Lr2Wq0Zx1Yc7Vb6Nm4Kj8Hg2Fd5Sa1Q= " +
            "password=hunter2 Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH mail me@example.com to 152.70.43.1:2053 nova-activation:1:AAAA"
        val out = LogSanitizer.sanitize(line)
        assertFalse(out.contains("3f2a9c1e"))
        assertFalse(out.contains("3aG8tN3s9uF5"))
        assertFalse(out.contains("hunter2"))
        assertFalse(out.contains("abcdefghijklmnopqrstuvwxyz0123456789"))
        assertFalse(out.contains("me@example.com"))
        assertFalse(out.contains("nova-activation:1:AAAA"))
        assertTrue(out.contains("152.70.43.1:2053"))
        assertTrue(out.startsWith("D/Xray: vless"))
    }

    @Test fun `leak and API verdicts`() {
        assertEquals("NO_LEAK_OBSERVED", LeakChecks.leakVerdict(dnsLeak = false, ipv6Egress = false))
        assertEquals("DNS_LEAK_SUSPECTED+IPV6_LEAK", LeakChecks.leakVerdict(dnsLeak = true, ipv6Egress = true))
        assertEquals("API_REACHABLE", ApiReachability.apiVerdict(400))
        assertEquals("API_RATE_LIMITED", ApiReachability.apiVerdict(429))
        assertEquals("API_SERVER_ERROR", ApiReachability.apiVerdict(503))
        assertEquals("API_UNREACHABLE", ApiReachability.apiVerdict(null))
    }

    @Test fun `exit reason names`() {
        assertEquals("EXIT_SELF", ExitReasons.reasonName(1))
        assertEquals("CRASH_NATIVE", ExitReasons.reasonName(5))
        assertEquals("CODE_99", ExitReasons.reasonName(99))
    }

    @Test fun `crash recorder keeps the newest five sanitized records`() {
        val dir = createTempDir("crash")
        try {
            repeat(7) { i -> CrashRecorder.record(dir, "main", IllegalStateException("boom uuid=3f2a9c1e-1b2c-4d5e-8f90-1234567890ab #$i"), 1_000L + i) }
            val files = java.io.File(dir, "support-diagnostics/crashes").listFiles()!!.map { it.name }.sorted()
            assertEquals(5, files.size)
            assertEquals("crash-1006.txt", files.last())
            val text = java.io.File(dir, "support-diagnostics/crashes/crash-1006.txt").readText()
            assertTrue(text.contains("IllegalStateException"))
            assertFalse(text.contains("3f2a9c1e"))
        } finally {
            dir.deleteRecursively()
        }
    }
}
