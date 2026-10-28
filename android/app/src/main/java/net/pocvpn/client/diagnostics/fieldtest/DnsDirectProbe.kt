package net.pocvpn.client.diagnostics.fieldtest

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

/*
 * Field-test direct resolver probe (observation only): asks the PHYSICAL network's own resolver for a
 * fixed list of names with hand-built UDP/53 packets and records the DNS header facts (RCODE, answer
 * count, bogon). It separates "the resolver answers NXDOMAIN / an empty answer / nothing / a bogus
 * address" from "the name does not exist" - which the system lookup alone (UnknownHostException) cannot.
 *
 * Reviewed limits: names come from a constant list, the resolver only from the physical network's
 * LinkProperties ([ProbeTargets.isAcceptableResolver]), responses are parsed defensively and capped at
 * 512 bytes, no EDNS, no TCP fallback, one socket per query, sequential per resolver, no retry storms.
 * No server bytes beyond the header facts and a bogon flag reach the report. Independent of the
 * transports (no vpn/ imports).
 */

enum class DnsQueryResult { ANSWER, NODATA, NXDOMAIN, SERVFAIL, REFUSED, OTHER_RCODE, TRUNCATED, TIMEOUT, INVALID_RESPONSE, SEND_FAILED, SKIPPED }

data class DnsQueryRecord(
    val host: String,
    val qtype: String,
    /** The resolver's address when it is public; "private" for a private-range resolver (a home router is not reported). */
    val resolver: String,
    val attempt: Int,
    val result: DnsQueryResult,
    val rcode: Int?,
    val answerCount: Int?,
    val bogon: Boolean?,
    val elapsedMs: Long,
    val note: String? = null,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("host", host)
        .put("qtype", qtype)
        .put("resolver", resolver)
        .put("attempt", attempt)
        .put("result", result.name)
        .put("rcode", rcode ?: JSONObject.NULL)
        .put("answerCount", answerCount ?: JSONObject.NULL)
        .put("bogon", bogon ?: JSONObject.NULL)
        .put("elapsedMs", elapsedMs)
        .put("note", note ?: JSONObject.NULL)
}

internal sealed interface DnsParse {
    data class Ok(val rcode: Int, val truncated: Boolean, val answerCount: Int, val addresses: List<String>) : DnsParse
    data class Invalid(val reason: String) : DnsParse
}

internal object DnsWire {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val MAX_RESPONSE = 512
    const val MAX_ANSWERS = 16

    /** Standard recursive query for [name] (labels <= 63, whole name <= 253). */
    fun buildQuery(id: Int, name: String, qtype: Int): ByteArray {
        require(name.isNotEmpty() && name.length <= 253)
        val out = java.io.ByteArrayOutputStream()
        out.write(id shr 8); out.write(id and 0xFF)
        out.write(0x01); out.write(0x00) // RD
        out.write(0); out.write(1) // QDCOUNT
        repeat(6) { out.write(0) } // AN, NS, AR
        name.split('.').forEach { label ->
            require(label.isNotEmpty() && label.length <= 63 && label.all { it.code in 0x21..0x7E })
            out.write(label.length); out.write(label.toByteArray(Charsets.US_ASCII))
        }
        out.write(0)
        out.write(qtype shr 8); out.write(qtype and 0xFF)
        out.write(0); out.write(1) // IN
        return out.toByteArray()
    }

    /** Defensive parse of a response to a query with [expectedId] / [qtype]. Never throws. */
    fun parse(buf: ByteArray, len: Int, expectedId: Int): DnsParse {
        if (len < 12 || len > MAX_RESPONSE || len > buf.size) return DnsParse.Invalid("length")
        fun u16(at: Int) = ((buf[at].toInt() and 0xFF) shl 8) or (buf[at + 1].toInt() and 0xFF)
        if (u16(0) != expectedId) return DnsParse.Invalid("id")
        val flags = u16(2)
        if (flags and 0x8000 == 0) return DnsParse.Invalid("not a response")
        val rcode = flags and 0x000F
        val truncated = flags and 0x0200 != 0
        if (u16(4) != 1) return DnsParse.Invalid("qdcount")
        val an = u16(6)
        if (an > MAX_ANSWERS) return DnsParse.Invalid("ancount")

        var pos = skipName(buf, len, 12)
        if (pos < 0 || pos + 4 > len) return DnsParse.Invalid("question")
        pos += 4
        val addresses = mutableListOf<String>()
        repeat(an) {
            pos = skipName(buf, len, pos)
            if (pos < 0 || pos + 10 > len) return DnsParse.Invalid("answer header")
            val type = u16(pos)
            val rdlen = u16(pos + 8)
            val rdata = pos + 10
            if (rdata + rdlen > len) return DnsParse.Invalid("rdlength")
            when {
                type == TYPE_A && rdlen == 4 -> addresses += (0 until 4).joinToString(".") { (buf[rdata + it].toInt() and 0xFF).toString() }
                type == TYPE_AAAA && rdlen == 16 ->
                    addresses += InetAddress.getByAddress(buf.copyOfRange(rdata, rdata + 16)).hostAddress.orEmpty()
                type == TYPE_A || type == TYPE_AAAA -> return DnsParse.Invalid("rdata size")
            }
            pos = rdata + rdlen
        }
        return DnsParse.Ok(rcode, truncated, an, addresses)
    }

    /**
     * Position after the name starting at [start], or -1. A compression pointer must point backwards inside
     * the packet; it is never followed (this parser only needs to skip), so a loop cannot occur.
     */
    private fun skipName(buf: ByteArray, len: Int, start: Int): Int {
        var pos = start
        var total = 0
        while (true) {
            if (pos >= len) return -1
            val b = buf[pos].toInt() and 0xFF
            when {
                b == 0 -> return pos + 1
                b and 0xC0 == 0xC0 -> {
                    if (pos + 1 >= len) return -1
                    val target = ((b and 0x3F) shl 8) or (buf[pos + 1].toInt() and 0xFF)
                    return if (target < pos) pos + 2 else -1
                }
                b and 0xC0 != 0 -> return -1 // reserved label types
                else -> {
                    total += b + 1
                    if (total > 255 || pos + 1 + b > len) return -1
                    pos += 1 + b
                }
            }
        }
    }
}

/** One UDP exchange. Real: a connected [DatagramSocket], so datagrams from any other source are dropped by the OS. */
internal fun interface DnsTransport {
    /** Returns the datagram (at most 513 bytes read) or throws [SocketTimeoutException] / an IO error. */
    fun exchange(resolverIp: String, query: ByteArray, timeoutMs: Int): ByteArray
}

internal object UdpDnsTransport : DnsTransport {
    override fun exchange(resolverIp: String, query: ByteArray, timeoutMs: Int): ByteArray =
        DatagramSocket().use { socket ->
            socket.soTimeout = timeoutMs
            val address = InetAddress.getByAddress(ProbeTargets.parseIpv4(resolverIp)!!.map { it.toByte() }.toByteArray())
            socket.connect(address, 53)
            socket.send(DatagramPacket(query, query.size))
            val buf = ByteArray(DnsWire.MAX_RESPONSE + 1)
            val packet = DatagramPacket(buf, buf.size)
            socket.receive(packet)
            buf.copyOf(packet.length)
        }
}

class DnsDirectProbe internal constructor(
    private val transport: DnsTransport,
    private val pause: suspend (Long) -> Unit,
    private val nowMs: () -> Long,
    private val nextId: () -> Int,
) {
    constructor() : this(
        transport = UdpDnsTransport,
        pause = { delay(it) },
        nowMs = { System.nanoTime() / 1_000_000 },
        nextId = { SecureRandom().nextInt(0x10000) },
    )

    /** At most [MAX_RESOLVERS] resolvers; unusable ones are skipped and reported once. */
    suspend fun run(resolvers: List<String>, names: List<String> = NAMES): List<DnsQueryRecord> = withContext(Dispatchers.IO) {
        val out = mutableListOf<DnsQueryRecord>()
        val usable = resolvers.distinct().filter { ProbeTargets.isAcceptableResolver(it) }.take(MAX_RESOLVERS)
        if (usable.isEmpty()) {
            out += DnsQueryRecord("-", "-", "none", 0, DnsQueryResult.SKIPPED, null, null, null, 0, note = "no usable resolver of the physical network")
            return@withContext out
        }
        for (resolver in usable) {
            val label = if (ProbeTargets.isPublicGateway(resolver)) resolver else "private"
            var consecutiveTimeouts = 0
            var abandoned = false
            for (attempt in 1..ATTEMPTS) {
                if (abandoned) break
                if (attempt > 1) pause(ATTEMPT_PAUSE_MS)
                for (name in names) {
                    // AAAA only once; A on every attempt, so a flaky resolver shows up as a pattern.
                    val types = if (attempt == 1) listOf(DnsWire.TYPE_A, DnsWire.TYPE_AAAA) else listOf(DnsWire.TYPE_A)
                    for (qtype in types) {
                        val record = query(resolver, label, name, qtype, attempt)
                        out += record
                        consecutiveTimeouts = if (record.result == DnsQueryResult.TIMEOUT) consecutiveTimeouts + 1 else 0
                        if (consecutiveTimeouts >= MAX_CONSECUTIVE_TIMEOUTS) {
                            out += DnsQueryRecord("-", "-", label, attempt, DnsQueryResult.SKIPPED, null, null, null, 0, note = "resolver silent after $MAX_CONSECUTIVE_TIMEOUTS timeouts")
                            abandoned = true
                            break
                        }
                    }
                    if (abandoned) break
                }
            }
        }
        out
    }

    private fun query(resolver: String, label: String, name: String, qtype: Int, attempt: Int): DnsQueryRecord {
        val typeName = if (qtype == DnsWire.TYPE_A) "A" else "AAAA"
        val id = nextId() and 0xFFFF
        val start = nowMs()
        fun record(result: DnsQueryResult, rcode: Int? = null, count: Int? = null, bogon: Boolean? = null, note: String? = null) =
            DnsQueryRecord(name, typeName, label, attempt, result, rcode, count, bogon, nowMs() - start, note)
        return try {
            val response = transport.exchange(resolver, DnsWire.buildQuery(id, name, qtype), TIMEOUT_MS)
            when (val parsed = DnsWire.parse(response, response.size, id)) {
                is DnsParse.Invalid -> record(DnsQueryResult.INVALID_RESPONSE, note = parsed.reason)
                is DnsParse.Ok -> {
                    val bogon = parsed.addresses.any { isBogon(it) }
                    val result = when {
                        parsed.truncated -> DnsQueryResult.TRUNCATED
                        parsed.rcode == 0 && parsed.answerCount > 0 -> DnsQueryResult.ANSWER
                        parsed.rcode == 0 -> DnsQueryResult.NODATA
                        parsed.rcode == 3 -> DnsQueryResult.NXDOMAIN
                        parsed.rcode == 2 -> DnsQueryResult.SERVFAIL
                        parsed.rcode == 5 -> DnsQueryResult.REFUSED
                        else -> DnsQueryResult.OTHER_RCODE
                    }
                    record(result, parsed.rcode, parsed.answerCount, bogon)
                }
            }
        } catch (e: SocketTimeoutException) {
            record(DnsQueryResult.TIMEOUT)
        } catch (e: Exception) {
            record(DnsQueryResult.SEND_FAILED, note = e.javaClass.simpleName)
        }
    }

    companion object {
        val NAMES = listOf("control.aknova.pp.ua", "edge-sthlm.aknova.pp.ua", "www.youtube.com", "www.google.com")
        const val MAX_RESOLVERS = 2
        const val ATTEMPTS = 3
        const val TIMEOUT_MS = 3_000
        const val ATTEMPT_PAUSE_MS = 1_000L
        const val MAX_CONSECUTIVE_TIMEOUTS = 3
    }
}

fun List<DnsQueryRecord>.toJsonArray(): JSONArray = JSONArray().also { a -> forEach { a.put(it.toJson()) } }
