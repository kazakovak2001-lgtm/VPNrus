package net.pocvpn.client.diagnostics.fieldtest

import java.net.ConnectException
import java.net.SocketTimeoutException
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class StageProbeTest {

    // --- target policy ----------------------------------------------------------------

    @Test fun strict_ipv4_parsing_rejects_everything_that_is_not_a_plain_dotted_quad() {
        for (bad in listOf("", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.04", "01.2.3.4", "1.2.3.-4", " 1.2.3.4", "1.2.3.4 ", "a.b.c.d", "2001:db8::1", "example.org", "1.2.3.", "1..2.3", "0x7f.0.0.1", "1.2.3.4/32", "99999999999")) {
            assertNull(bad, ProbeTargets.parseIpv4(bad))
        }
        assertArrayEquals(intArrayOf(152, 70, 43, 1), ProbeTargets.parseIpv4("152.70.43.1"))
        assertArrayEquals(intArrayOf(0, 0, 0, 0), ProbeTargets.parseIpv4("0.0.0.0"))
    }

    @Test fun only_public_ipv4_literals_are_gateway_targets() {
        for (ok in listOf("152.70.43.1", "16.170.208.231", "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1", "198.17.0.1", "198.20.0.1")) assertTrue(ok, ProbeTargets.isPublicGateway(ok))
        for (bad in listOf(
            "0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.255.255.255", "169.254.1.1",
            "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
            "198.51.100.7", "203.0.113.5", "224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255",
            "localhost", "example.org", "::1", "2606:4700::1111",
        )) assertFalse(bad, ProbeTargets.isPublicGateway(bad))
    }

    @Test fun resolvers_may_be_private_but_never_loopback_any_local_multicast_or_reserved() {
        for (ok in listOf("192.168.1.1", "10.0.0.2", "193.232.160.49", "8.8.8.8", "100.64.0.1")) assertTrue(ok, ProbeTargets.isAcceptableResolver(ok))
        for (bad in listOf("0.0.0.0", "127.0.0.1", "127.0.0.53", "224.0.0.251", "240.0.0.1", "255.255.255.255", "", "localhost", "::1")) assertFalse(bad, ProbeTargets.isAcceptableResolver(bad))
    }

    // --- the ClientHello --------------------------------------------------------------

    private val random = ByteArray(32) { it.toByte() }
    private val keyShare = ByteArray(32) { (32 + it).toByte() }

    @Test fun clientHello_without_sni_has_the_documented_fixed_shape() {
        val h = StageClientHello.build(null, random, keyShare)
        assertEquals(159, h.size)
        assertEquals(0x16, h[0].toInt() and 0xFF)
        assertEquals(0x03, h[1].toInt()); assertEquals(0x01, h[2].toInt()) // record version 3.1
        assertEquals(h.size - 5, ((h[3].toInt() and 0xFF) shl 8) or (h[4].toInt() and 0xFF))
        assertEquals(0x01, h[5].toInt()) // ClientHello
        assertEquals(h.size - 9, ((h[6].toInt() and 0xFF) shl 16) or ((h[7].toInt() and 0xFF) shl 8) or (h[8].toInt() and 0xFF))
        assertEquals(0x03, h[9].toInt()); assertEquals(0x03, h[10].toInt()) // client_version 3.3
        assertArrayEquals(random, h.copyOfRange(11, 43))
        assertEquals(0, h[43].toInt()) // empty session id
        assertEquals(18, ((h[44].toInt() and 0xFF) shl 8) or (h[45].toInt() and 0xFF)) // 9 suites
        assertEquals(0x13, h[46].toInt()); assertEquals(0x01, h[47].toInt()) // first suite TLS_AES_128_GCM_SHA256
        assertEquals(1, h[64].toInt()); assertEquals(0, h[65].toInt()) // compression: null only
        assertTrue(String(h, Charsets.ISO_8859_1).indexOf("example") < 0)
    }

    @Test fun clientHello_with_sni_adds_exactly_the_server_name_extension() {
        val without = StageClientHello.build(null, random, keyShare)
        val with = StageClientHello.build("www.example.org", random, keyShare)
        assertEquals(without.size + 24, with.size) // 4 (ext header) + 2 + 3 + 15
        assertTrue(String(with, Charsets.ISO_8859_1).contains("www.example.org"))
        assertEquals(with.size - 5, ((with[3].toInt() and 0xFF) shl 8) or (with[4].toInt() and 0xFF))
    }

    @Test fun clientHello_is_deterministic_for_the_same_inputs() {
        assertArrayEquals(StageClientHello.build("a.test", random, keyShare), StageClientHello.build("a.test", random, keyShare))
    }

    @Test fun clientHello_rejects_unusable_names_and_inputs() {
        for (bad in listOf("", "bad name", "x".repeat(254), "ünicode.test")) {
            assertTrue(bad, runCatching { StageClientHello.build(bad, random, keyShare) }.isFailure)
        }
        assertTrue(runCatching { StageClientHello.build(null, ByteArray(31), keyShare) }.isFailure)
    }

    // --- the probe --------------------------------------------------------------------

    private class FakeConn(private val replies: ArrayDeque<() -> ByteArray>) : StageConnection {
        val sent = mutableListOf<ByteArray>()
        var closed = false
        override fun send(bytes: ByteArray) { sent += bytes }
        override fun read(max: Int, timeoutMs: Int): ByteArray = replies.removeFirst()().let { if (it.size > max) it.copyOf(max) else it }
        override fun close() { closed = true }
    }

    private class FakeConnector(private val script: (Int) -> Result<FakeConn>) : StageConnector {
        val opens = mutableListOf<Pair<String, Int>>()
        val conns = mutableListOf<FakeConn>()
        override fun open(host: String, port: Int, connectTimeoutMs: Int): StageConnection {
            opens += host to port
            return script(opens.size).getOrThrow().also { conns += it }
        }
    }

    private fun conn(vararg replies: () -> ByteArray) = FakeConn(ArrayDeque(replies.toList()))
    private val handshake = { byteArrayOf(0x16, 3, 3, 0, 90) }
    private val alert = { byteArrayOf(0x15, 3, 3, 0, 2) }
    private val timeout: () -> ByteArray = { throw SocketTimeoutException() }
    private val closed = { ByteArray(0) }

    private fun probe(connector: StageConnector, clock: () -> Long = { 0L }, pauses: MutableList<Long> = mutableListOf()) =
        StageProbe(connector, pause = { pauses += it }, nowMs = clock, randomBytes = { n -> ByteArray(n) })

    private val tlsBinding = EndpointTransportBinding(TransportKind.TLS_TCP, "16.170.208.231", 2083)

    @Test fun a_server_that_answers_every_hello_yields_no_failed_stage() = runBlocking {
        val connector = FakeConnector { n -> Result.success(if (n == 1) conn(handshake) else conn(alert)) }
        val pauses = mutableListOf<Long>()
        val r = probe(connector, pauses = pauses).probe("stockholm", tlsBinding)
        assertEquals(listOf(StageName.TCP_CONNECT, StageName.TLS_NO_SNI, StageName.TLS_NEUTRAL_SNI, StageName.TLS_REAL_SNI), r.stages.map { it.stage })
        assertEquals(listOf(StageResult.OK, StageResult.HANDSHAKE, StageResult.ALERT, StageResult.SKIPPED), r.stages.map { it.result })
        assertNull(r.firstFailedStage)
        assertEquals("3.3", r.stages[1].recordVersion)
        assertEquals(0x16, r.stages[1].recordType)
        assertEquals("no SNI known from the signed profile", r.stages[3].note)
        // stage 1's connection carries the first hello; the neutral-SNI hello needs a second connection
        assertEquals(2, connector.opens.size)
        assertTrue(connector.conns.all { it.closed })
        assertEquals(listOf(1_000L), pauses) // one pause before the neutral-SNI stage, never a burst
    }

    @Test fun the_field_hypothesis_shape_tcp_ok_and_no_sni_hello_times_out_while_the_neutral_one_is_answered() = runBlocking {
        val connector = FakeConnector { n -> Result.success(if (n == 1) conn(timeout) else conn(handshake)) }
        val r = probe(connector).probe("stockholm", tlsBinding)
        assertEquals(StageResult.TIMEOUT, r.stages[1].result)
        assertEquals("SocketTimeoutException", r.stages[1].errorType)
        assertEquals(StageResult.HANDSHAKE, r.stages[2].result)
        assertEquals(StageName.TLS_NO_SNI, r.firstFailedStage)
    }

    @Test fun a_closed_connection_is_close_and_an_early_reset_is_not_confused_with_it() = runBlocking {
        val connector = FakeConnector { n -> Result.success(if (n == 1) conn(closed) else conn({ throw java.net.SocketException("x") })) }
        val r = probe(connector).probe("e", tlsBinding)
        assertEquals(StageResult.CLOSE, r.stages[1].result)
        assertEquals(StageResult.OTHER, r.stages[2].result) // an unclassifiable IO error is OTHER, not RESET
    }

    @Test fun a_non_tls_reply_is_reported_as_such() = runBlocking {
        val connector = FakeConnector { _ -> Result.success(conn({ "HTTP/".toByteArray() })) }
        val r = probe(connector).probe("e", tlsBinding)
        assertEquals(StageResult.NOT_TLS, r.stages[1].result)
        assertEquals(0x48, r.stages[1].recordType)
    }

    @Test fun a_failed_tcp_connect_stops_the_probe_after_one_stage() = runBlocking {
        val connector = FakeConnector { Result.failure(ConnectException("refused")) }
        val r = probe(connector).probe("e", tlsBinding)
        assertEquals(listOf(StageName.TCP_CONNECT), r.stages.map { it.stage })
        assertEquals(StageName.TCP_CONNECT, r.firstFailedStage)
        assertEquals("ConnectException", r.stages[0].errorType)
        assertEquals(1, connector.opens.size)
    }

    @Test fun the_real_sni_stage_runs_only_with_an_sni_from_the_signed_profile() = runBlocking {
        val connector = FakeConnector { _ -> Result.success(conn(handshake)) }
        val r = probe(connector).probe("e", tlsBinding, realSni = "gw.example.net")
        assertEquals(StageResult.HANDSHAKE, r.stages.last().result)
        assertTrue(connector.conns.last().sent.single().let { String(it, Charsets.ISO_8859_1).contains("gw.example.net") })
    }

    @Test fun a_stage_that_would_exceed_the_time_budget_is_skipped_not_started() = runBlocking {
        var now = 0L
        val connector = FakeConnector { _ -> Result.success(conn({ now += 12_000; handshake() })) }
        val r = probe(connector, clock = { now }).probe("e", tlsBinding)
        assertEquals(StageResult.HANDSHAKE, r.stages[1].result)
        assertEquals(StageResult.SKIPPED, r.stages[2].result)
        assertEquals("time budget", r.stages[2].note)
        assertEquals(1, connector.opens.size)
    }

    @Test fun targets_that_fail_the_policy_are_refused_before_any_connection() = runBlocking {
        val connector = FakeConnector { error("must not connect") }
        for (host in listOf("127.0.0.1", "10.0.0.5", "192.168.1.9", "100.64.0.9", "203.0.113.8", "localhost", "edge.example.org", "2606:4700::1111", "1.2.3")) {
            val r = probe(connector).probe("e", EndpointTransportBinding(TransportKind.TLS_TCP, host, 2083))
            assertEquals(host, "target is not a public IPv4 literal", r.rejected)
            assertTrue(r.stages.isEmpty())
        }
        assertTrue(connector.opens.isEmpty())
    }

    @Test fun only_tls_tcp_bindings_are_probed() = runBlocking {
        val connector = FakeConnector { error("must not connect") }
        for (kind in TransportKind.entries.filter { it != TransportKind.TLS_TCP }) {
            val r = probe(connector).probe("e", EndpointTransportBinding(kind, "16.170.208.231", 2053))
            assertEquals("transport not probed", r.rejected)
        }
        assertTrue(connector.opens.isEmpty())
    }

    @Test fun failures_are_classified_by_exception_type_and_errno_not_by_message() {
        val errno = { e: Throwable -> (e as? FakeErrno)?.code }
        fun c(e: Throwable) = classifyStageFailure(e, errno, reset = setOf(104), refused = setOf(111), noRoute = setOf(101))
        assertEquals(StageResult.TIMEOUT, c(SocketTimeoutException("connection reset")))
        assertEquals(StageResult.RESET, c(java.net.SocketException("x").apply { initCause(FakeErrno(104)) }))
        assertEquals(StageResult.REFUSED, c(ConnectException("x").apply { initCause(FakeErrno(111)) }))
        assertEquals(StageResult.NO_ROUTE, c(java.net.SocketException("x").apply { initCause(FakeErrno(101)) }))
        assertEquals(StageResult.OTHER, c(java.net.SocketException("Connection reset by peer")))
    }

    private class FakeErrno(val code: Int) : Exception()

    // --- report -----------------------------------------------------------------------

    @Test fun the_report_json_carries_only_stage_facts_no_server_bytes() = runBlocking {
        val connector = FakeConnector { n -> Result.success(if (n == 1) conn(timeout) else conn(handshake)) }
        val json = probe(connector).probe("stockholm", tlsBinding).toJson()
        assertEquals(setOf("endpointId", "transport", "host", "port", "rejected", "firstFailedStage", "stages"), json.keys().asSequence().toSet())
        val stage = json.getJSONArray("stages").getJSONObject(1)
        assertEquals(setOf("stage", "result", "elapsedMs", "errorType", "recordType", "recordVersion", "note"), stage.keys().asSequence().toSet())
        assertEquals("TLS_NO_SNI", json.getString("firstFailedStage"))
    }

    @Test fun the_summary_line_names_the_first_failed_stage() = runBlocking {
        val connector = FakeConnector { n -> Result.success(if (n == 1) conn(timeout) else conn(handshake)) }
        val line = probe(connector).probe("stockholm", tlsBinding).summaryLine()
        assertTrue(line, "first failed: TLS_NO_SNI" in line)
        assertTrue(line, "tls_no_sni TIMEOUT" in line)
    }
}
