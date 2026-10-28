package net.pocvpn.client.diagnostics.fieldtest

import java.net.SocketTimeoutException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsDirectProbeTest {

    // --- wire format ------------------------------------------------------------------

    @Test fun query_is_a_standard_recursive_question() {
        val q = DnsWire.buildQuery(0x1234, "control.aknova.pp.ua", DnsWire.TYPE_A)
        assertEquals(0x12, q[0].toInt()); assertEquals(0x34, q[1].toInt())
        assertEquals(0x01, q[2].toInt()); assertEquals(0x00, q[3].toInt()) // RD
        assertEquals(1, q[5].toInt()) // QDCOUNT
        assertEquals(7, q[12].toInt()) // "control"
        assertEquals(12 + (1 + 7) + (1 + 6) + (1 + 2) + (1 + 2) + 1 + 4, q.size) // header + 4 labels + root + type/class
        assertEquals(0, q[q.size - 5].toInt()) // root label
        assertEquals(1, q[q.size - 3].toInt()); assertEquals(1, q[q.size - 1].toInt()) // type A, class IN
    }

    @Test fun query_builder_rejects_oversized_or_malformed_names() {
        for (bad in listOf("", "a".repeat(64) + ".test", "a..b", "x".repeat(254), "sp ace.test")) {
            assertTrue(bad, runCatching { DnsWire.buildQuery(1, bad, DnsWire.TYPE_A) }.isFailure)
        }
    }

    /** Hand-assembled response to a query for "a.test": [answers] = (type, rdata) with a compression pointer to the question. */
    private fun response(
        id: Int = 0x1234,
        flags: Int = 0x8180,
        qdcount: Int = 1,
        answers: List<Pair<Int, ByteArray>> = emptyList(),
        ancount: Int = answers.size,
        rdlenOverride: Int? = null,
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        fun u16(v: Int) { out.write(v shr 8); out.write(v and 0xFF) }
        u16(id); u16(flags); u16(qdcount); u16(ancount); u16(0); u16(0)
        out.write(1); out.write('a'.code); out.write(4); out.write("test".toByteArray()); out.write(0); u16(1); u16(1)
        for ((type, rdata) in answers) {
            out.write(0xC0); out.write(12) // pointer back to the question name
            u16(type); u16(1); u16(0); u16(60); u16(rdlenOverride ?: rdata.size); out.write(rdata)
        }
        return out.toByteArray()
    }

    private fun parse(buf: ByteArray, id: Int = 0x1234) = DnsWire.parse(buf, buf.size, id)

    @Test fun an_answer_is_parsed_with_rcode_count_and_address() {
        val ok = parse(response(answers = listOf(DnsWire.TYPE_A to byteArrayOf(0x10, 0xAA.toByte(), 0xD0.toByte(), 0xE7.toByte())))) as DnsParse.Ok
        assertEquals(0, ok.rcode)
        assertEquals(1, ok.answerCount)
        assertEquals(listOf("16.170.208.231"), ok.addresses)
    }

    @Test fun nxdomain_and_empty_noerror_are_distinguished() {
        assertEquals(3, (parse(response(flags = 0x8183)) as DnsParse.Ok).rcode)
        val nodata = parse(response()) as DnsParse.Ok
        assertEquals(0, nodata.rcode); assertEquals(0, nodata.answerCount)
    }

    @Test fun an_aaaa_answer_is_formatted_without_any_lookup() {
        val v6 = ByteArray(16).also { it[0] = 0x26; it[1] = 0x06; it[15] = 0x11 }
        val ok = parse(response(answers = listOf(DnsWire.TYPE_AAAA to v6))) as DnsParse.Ok
        assertEquals(1, ok.addresses.size)
        assertTrue(ok.addresses.single().startsWith("2606:"))
    }

    @Test fun truncation_is_reported_and_other_record_types_are_skipped() {
        val tc = parse(response(flags = 0x8380)) as DnsParse.Ok
        assertTrue(tc.truncated)
        val cname = parse(response(answers = listOf(5 to byteArrayOf(1, 'b'.code.toByte(), 0)))) as DnsParse.Ok
        assertEquals(1, cname.answerCount); assertTrue(cname.addresses.isEmpty())
    }

    @Test fun malformed_responses_are_invalid_and_never_throw() {
        fun invalid(b: ByteArray, id: Int = 0x1234) = parse(b, id) is DnsParse.Invalid
        assertTrue("wrong id", invalid(response(id = 0x4321)))
        assertTrue("not a response", invalid(response(flags = 0x0100)))
        assertTrue("two questions", invalid(response(qdcount = 2)))
        assertTrue("too many answers", invalid(response(ancount = 17)))
        assertTrue("truncated packet", invalid(response().copyOf(11)))
        assertTrue("answers missing", invalid(response(ancount = 3)))
        assertTrue("rdlength past the end", invalid(response(answers = listOf(DnsWire.TYPE_A to byteArrayOf(1, 2, 3, 4)), rdlenOverride = 200)))
        assertTrue("A with 5 bytes", invalid(response(answers = listOf(DnsWire.TYPE_A to byteArrayOf(1, 2, 3, 4, 5)))))
        assertTrue("empty", DnsWire.parse(ByteArray(0), 0, 1) is DnsParse.Invalid)
        assertTrue("oversized", DnsWire.parse(ByteArray(600), 600, 0) is DnsParse.Invalid)
        assertTrue("len beyond buffer", DnsWire.parse(ByteArray(20), 40, 0) is DnsParse.Invalid)
    }

    @Test fun compression_pointers_must_point_backwards_and_are_never_followed() {
        val good = response(answers = listOf(DnsWire.TYPE_A to byteArrayOf(1, 2, 3, 4)))
        assertTrue(parse(good) is DnsParse.Ok)
        // a pointer to itself (a loop) and a forward pointer
        val self = good.copyOf().also { val at = good.size - 4 - 10 - 2; it[at] = 0xC0.toByte(); it[at + 1] = at.toByte() }
        val forward = good.copyOf().also { val at = good.size - 4 - 10 - 2; it[at] = 0xC0.toByte(); it[at + 1] = (at + 5).toByte() }
        assertTrue(parse(self) is DnsParse.Invalid)
        assertTrue(parse(forward) is DnsParse.Invalid)
    }

    @Test fun reserved_label_types_and_overlong_labels_are_invalid() {
        val bad = response(answers = listOf(DnsWire.TYPE_A to byteArrayOf(1, 2, 3, 4)))
        val at = bad.size - 4 - 10 - 2
        val reserved = bad.copyOf().also { it[at] = 0x80.toByte() }
        assertTrue(parse(reserved) is DnsParse.Invalid)
        val overlong = bad.copyOf().also { it[12] = 0x3F } // a 63-byte label that runs past the question
        assertTrue(parse(overlong) is DnsParse.Invalid)
    }

    // --- the probe --------------------------------------------------------------------

    private class FakeDns(private val onQuery: (resolver: String, id: Int, name: String, qtype: Int, n: Int) -> ByteArray) : DnsTransport {
        val log = mutableListOf<Triple<String, String, Int>>()
        override fun exchange(resolverIp: String, query: ByteArray, timeoutMs: Int): ByteArray {
            val id = ((query[0].toInt() and 0xFF) shl 8) or (query[1].toInt() and 0xFF)
            val qtype = ((query[query.size - 4].toInt() and 0xFF) shl 8) or (query[query.size - 3].toInt() and 0xFF)
            val name = StringBuilder().also { sb ->
                var i = 12
                while (query[i].toInt() != 0) { val l = query[i].toInt(); if (sb.isNotEmpty()) sb.append('.'); sb.append(String(query, i + 1, l)); i += l + 1 }
            }.toString()
            log += Triple(resolverIp, name, qtype)
            return onQuery(resolverIp, id, name, qtype, log.size)
        }
    }

    private fun reply(id: Int, flags: Int = 0x8180, answers: List<Pair<Int, ByteArray>> = emptyList()): ByteArray {
        val b = response(id = id, flags = flags, answers = answers)
        return b // question name is fixed ("a.test"); the parser only checks structure and id
    }

    private fun probe(transport: DnsTransport, pauses: MutableList<Long> = mutableListOf()) =
        DnsDirectProbe(transport, pause = { pauses += it }, nowMs = { 0L }, nextId = { 0x1111 })

    @Test fun the_field_shape_nxdomain_for_the_nova_names_and_an_answer_for_google_is_visible_per_name() = runBlocking {
        val dns = FakeDns { _, id, name, qtype, _ ->
            when {
                name.endsWith("aknova.pp.ua") -> reply(id, flags = 0x8183)
                qtype == DnsWire.TYPE_A -> reply(id, answers = listOf(DnsWire.TYPE_A to byteArrayOf(8, 8, 8, 8)))
                else -> reply(id)
            }
        }
        val records = probe(dns).run(listOf("193.232.160.49"))
        val control = records.filter { it.host == "control.aknova.pp.ua" && it.qtype == "A" }
        assertEquals(listOf(DnsQueryResult.NXDOMAIN, DnsQueryResult.NXDOMAIN, DnsQueryResult.NXDOMAIN), control.map { it.result })
        assertEquals(listOf(3, 3, 3), control.map { it.rcode })
        assertEquals(listOf(1, 2, 3), control.map { it.attempt })
        assertTrue(records.filter { it.host == "www.google.com" && it.qtype == "A" }.all { it.result == DnsQueryResult.ANSWER && it.bogon == false })
        // AAAA only on the first attempt
        assertEquals(1, records.count { it.host == "www.google.com" && it.qtype == "AAAA" })
        assertEquals("193.232.160.49", records.first().resolver)
    }

    @Test fun an_empty_noerror_is_nodata_and_a_bogus_address_sets_the_bogon_flag() = runBlocking {
        val dns = FakeDns { _, id, name, _, _ ->
            when (name) {
                "control.aknova.pp.ua" -> reply(id)
                "www.youtube.com" -> reply(id, answers = listOf(DnsWire.TYPE_A to byteArrayOf(127, 0, 0, 2)))
                else -> reply(id, flags = 0x8182)
            }
        }
        val records = probe(dns).run(listOf("8.8.8.8"))
        assertEquals(DnsQueryResult.NODATA, records.first { it.host == "control.aknova.pp.ua" }.result)
        val yt = records.first { it.host == "www.youtube.com" && it.qtype == "A" }
        assertEquals(DnsQueryResult.ANSWER, yt.result); assertEquals(true, yt.bogon)
        assertEquals(DnsQueryResult.SERVFAIL, records.first { it.host == "www.google.com" }.result)
    }

    @Test fun a_silent_resolver_is_abandoned_after_three_timeouts_not_hammered() = runBlocking {
        val dns = FakeDns { _, _, _, _, _ -> throw SocketTimeoutException() }
        val records = probe(dns).run(listOf("193.232.160.49"))
        assertEquals(3, dns.log.size)
        assertEquals(3, records.count { it.result == DnsQueryResult.TIMEOUT })
        assertEquals("resolver silent after 3 timeouts", records.last().note)
    }

    @Test fun attempts_are_spaced_apart_and_a_bad_response_is_invalid_not_an_exception() = runBlocking {
        val pauses = mutableListOf<Long>()
        val dns = FakeDns { _, _, _, _, _ -> ByteArray(7) }
        val records = probe(dns, pauses).run(listOf("8.8.8.8"))
        assertTrue(records.all { it.result == DnsQueryResult.INVALID_RESPONSE })
        assertEquals(listOf(1_000L, 1_000L), pauses)
        assertEquals(4 * 2 + 4 * 2, records.size) // (A+AAAA) once, A twice more, 4 names
    }

    @Test fun unusable_resolvers_are_never_queried_and_private_ones_are_not_named() = runBlocking {
        val dns = FakeDns { _, id, _, _, _ -> reply(id) }
        val none = probe(dns).run(listOf("127.0.0.1", "0.0.0.0", "224.0.0.1", "example.org"))
        assertTrue(dns.log.isEmpty())
        assertEquals(DnsQueryResult.SKIPPED, none.single().result)

        val records = probe(dns).run(listOf("192.168.1.1", "193.232.160.49", "8.8.8.8"))
        assertEquals(setOf("192.168.1.1", "193.232.160.49"), dns.log.map { it.first }.toSet()) // at most two resolvers
        assertEquals(setOf("private", "193.232.160.49"), records.map { it.resolver }.toSet())
        assertFalse(records.any { it.resolver == "192.168.1.1" })
    }

    @Test fun the_record_json_carries_only_header_facts() = runBlocking {
        val dns = FakeDns { _, id, _, _, _ -> reply(id, answers = listOf(DnsWire.TYPE_A to byteArrayOf(8, 8, 8, 8))) }
        val json = probe(dns).run(listOf("8.8.8.8")).first().toJson()
        assertEquals(setOf("host", "qtype", "resolver", "attempt", "result", "rcode", "answerCount", "bogon", "elapsedMs", "note"), json.keys().asSequence().toSet())
    }
}
