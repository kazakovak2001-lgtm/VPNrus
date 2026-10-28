package net.pocvpn.client.diagnostics.fieldtest

import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import org.json.JSONArray
import org.json.JSONObject

/*
 * Field-test stage probe (observation only). For a TLS_TCP gateway port it separates WHICH step fails
 * on a restricted network: TCP connect, a TLS ClientHello without SNI, with a neutral SNI, and with the
 * real SNI when one is known. It answers "what does the first server record look like", nothing more.
 *
 * Security (reviewed): there is NO TLS library, NO TrustManager, NO HostnameVerifier and NO
 * SSLSocketFactory here. A plain Socket sends one hand-built ClientHello and reads at most the
 * 5-byte record header; no key exchange, no certificate, no data is ever exchanged, and the
 * connection is closed straight away. Targets are public IPv4 literals of the signed manifest only
 * ([ProbeTargets]). This file must stay independent of the transports (no vpn/ imports).
 */

enum class StageName { TCP_CONNECT, TLS_NO_SNI, TLS_NEUTRAL_SNI, TLS_REAL_SNI }

enum class StageResult {
    /** TCP connected. */
    OK,

    /** The first record is a TLS handshake record (a ServerHello follows). */
    HANDSHAKE,

    /** The first record is a TLS alert: the server speaks TLS and refused. */
    ALERT,

    /** The first record is not TLS. */
    NOT_TLS,

    /** The server closed the connection without sending a record. */
    CLOSE,
    RESET,
    REFUSED,
    NO_ROUTE,
    TIMEOUT,
    OTHER,

    /** Not attempted (see [StageOutcome.note]). */
    SKIPPED,
    ;

    /** True for results that mean the step did not get an answer. */
    val failed: Boolean get() = this in FAILED

    private companion object {
        val FAILED = setOf(CLOSE, RESET, REFUSED, NO_ROUTE, TIMEOUT, OTHER, NOT_TLS)
    }
}

data class StageOutcome(
    val stage: StageName,
    val result: StageResult,
    val elapsedMs: Long,
    /** Exception class name only - never a message (it could echo local addresses). */
    val errorType: String? = null,
    /** TLS record type of the first server record (0x16 handshake, 0x15 alert), when one arrived. */
    val recordType: Int? = null,
    /** "major.minor" from the record header, e.g. "3.3". */
    val recordVersion: String? = null,
    val note: String? = null,
)

data class StageProbeResult(
    val endpointId: String,
    val transport: String,
    val host: String,
    val port: Int,
    /** Non-null when the target was refused BEFORE any connection (nothing was sent). */
    val rejected: String?,
    val stages: List<StageOutcome>,
) {
    /** First step that got no answer; null when every attempted step was answered. */
    val firstFailedStage: StageName? get() = stages.firstOrNull { it.result.failed }?.stage

    fun toJson(): JSONObject = JSONObject()
        .put("endpointId", endpointId)
        .put("transport", transport)
        .put("host", host)
        .put("port", port)
        .put("rejected", rejected ?: JSONObject.NULL)
        .put("firstFailedStage", firstFailedStage?.name ?: JSONObject.NULL)
        .put(
            "stages",
            JSONArray().apply {
                stages.forEach { s ->
                    put(
                        JSONObject()
                            .put("stage", s.stage.name)
                            .put("result", s.result.name)
                            .put("elapsedMs", s.elapsedMs)
                            .put("errorType", s.errorType ?: JSONObject.NULL)
                            .put("recordType", s.recordType ?: JSONObject.NULL)
                            .put("recordVersion", s.recordVersion ?: JSONObject.NULL)
                            .put("note", s.note ?: JSONObject.NULL),
                    )
                }
            },
        )

    fun summaryLine(): String =
        if (rejected != null) {
            "  stage probe $transport $host:$port: refused before connecting ($rejected)"
        } else {
            "  stage probe $transport $host:$port: " + stages.joinToString(", ") { s ->
                "${s.stage.name.lowercase()} ${s.result}${if (s.result == StageResult.SKIPPED) "" else " ${s.elapsedMs}ms"}"
            } + (firstFailedStage?.let { " -> first failed: ${it.name}" } ?: "")
        }
}

/** The one TLS ClientHello this probe sends. Deterministic given its two random inputs. */
internal object StageClientHello {
    private val CIPHER_SUITES = intArrayOf(0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8)
    private val GROUPS = intArrayOf(0x001D, 0x0017, 0x0018)
    private val SIGNATURE_ALGORITHMS = intArrayOf(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601)

    /**
     * [random] (32 bytes) and [keyShare] (32 bytes, an x25519 share that is never used) come from the
     * caller so a test can pin the exact bytes. [sni] null -> no server_name extension.
     */
    fun build(sni: String?, random: ByteArray, keyShare: ByteArray): ByteArray {
        require(random.size == 32 && keyShare.size == 32)
        sni?.let { require(it.isNotEmpty() && it.length <= 253 && it.all { c -> c.code in 0x21..0x7E }) { "invalid sni" } }

        val ext = Buf()
        sni?.let { name ->
            val bytes = name.toByteArray(Charsets.US_ASCII)
            ext.u16(0x0000).u16(bytes.size + 5).u16(bytes.size + 3).u8(0).u16(bytes.size).raw(bytes)
        }
        ext.u16(0x000A).u16(2 + GROUPS.size * 2).u16(GROUPS.size * 2).apply { GROUPS.forEach { u16(it) } }
        ext.u16(0x000B).u16(2).u8(1).u8(0)
        ext.u16(0x000D).u16(2 + SIGNATURE_ALGORITHMS.size * 2).u16(SIGNATURE_ALGORITHMS.size * 2).apply { SIGNATURE_ALGORITHMS.forEach { u16(it) } }
        ext.u16(0x002B).u16(5).u8(4).u16(0x0304).u16(0x0303)
        ext.u16(0x0033).u16(2 + 4 + 32).u16(4 + 32).u16(0x001D).u16(32).raw(keyShare)

        val body = Buf()
        body.u16(0x0303).raw(random).u8(0) // client_version, random, empty session id
        body.u16(CIPHER_SUITES.size * 2).apply { CIPHER_SUITES.forEach { u16(it) } }
        body.u8(1).u8(0) // compression: null only
        body.u16(ext.size).raw(ext.bytes())

        val handshake = Buf().u8(0x01).u24(body.size).raw(body.bytes())
        return Buf().u8(0x16).u16(0x0301).u16(handshake.size).raw(handshake.bytes()).bytes()
    }

    private class Buf {
        private val out = java.io.ByteArrayOutputStream()
        val size: Int get() = out.size()
        fun u8(v: Int) = apply { out.write(v and 0xFF) }
        fun u16(v: Int) = apply { out.write((v shr 8) and 0xFF); out.write(v and 0xFF) }
        fun u24(v: Int) = apply { out.write((v shr 16) and 0xFF); out.write((v shr 8) and 0xFF); out.write(v and 0xFF) }
        fun raw(b: ByteArray) = apply { out.write(b) }
        fun bytes(): ByteArray = out.toByteArray()
    }
}

/** One open TCP connection as the probe needs it. Blocking; the real one is a plain [Socket]. */
internal interface StageConnection {
    fun send(bytes: ByteArray)

    /** Reads up to [max] bytes within [timeoutMs]; an empty array means the peer closed. Throws on timeout/IO error. */
    fun read(max: Int, timeoutMs: Int): ByteArray
    fun close()
}

internal fun interface StageConnector {
    fun open(host: String, port: Int, connectTimeoutMs: Int): StageConnection
}

internal object SocketStageConnector : StageConnector {
    override fun open(host: String, port: Int, connectTimeoutMs: Int): StageConnection {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress(host, port), connectTimeoutMs)
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
        return object : StageConnection {
            override fun send(bytes: ByteArray) {
                socket.getOutputStream().apply { write(bytes); flush() }
            }

            override fun read(max: Int, timeoutMs: Int): ByteArray {
                socket.soTimeout = timeoutMs
                val buf = ByteArray(max)
                val n = socket.getInputStream().read(buf)
                return if (n <= 0) ByteArray(0) else buf.copyOf(n)
            }

            override fun close() {
                runCatching { socket.close() }
            }
        }
    }
}

/** Maps a failure to a result by exception TYPE / errno, never by message text. */
internal fun classifyStageFailure(
    e: Throwable,
    errnoOf: (Throwable) -> Int? = { (it as? android.system.ErrnoException)?.errno },
    reset: Set<Int> = setOf(android.system.OsConstants.ECONNRESET, android.system.OsConstants.EPIPE),
    refused: Set<Int> = setOf(android.system.OsConstants.ECONNREFUSED),
    noRoute: Set<Int> = setOf(android.system.OsConstants.ENETUNREACH, android.system.OsConstants.EHOSTUNREACH),
): StageResult {
    val chain = generateSequence(e) { it.cause }.take(6).toList()
    return when {
        chain.any { it is SocketTimeoutException } -> StageResult.TIMEOUT
        chain.any { e2 -> errnoOf(e2)?.let { n -> n in refused } == true } -> StageResult.REFUSED
        chain.any { e2 -> errnoOf(e2)?.let { n -> n in reset } == true } -> StageResult.RESET
        chain.any { e2 -> errnoOf(e2)?.let { n -> n in noRoute } == true } -> StageResult.NO_ROUTE
        else -> StageResult.OTHER
    }
}

class StageProbe internal constructor(
    private val connector: StageConnector,
    private val pause: suspend (Long) -> Unit,
    private val nowMs: () -> Long,
    private val randomBytes: (Int) -> ByteArray,
) {
    constructor() : this(
        connector = SocketStageConnector,
        pause = { delay(it) },
        nowMs = { System.nanoTime() / 1_000_000 },
        randomBytes = { n -> ByteArray(n).also { SecureRandom().nextBytes(it) } },
    )

    /**
     * Probes ONE manifest binding. Only TLS_TCP is probed: on REALITY ports a foreign ClientHello is always
     * forwarded to the decoy, so the answer would say nothing (and cost a recognisable probe). [realSni]
     * is used only when it comes from the signed profile; null -> that step is SKIPPED, never guessed.
     */
    suspend fun probe(endpointId: String, binding: EndpointTransportBinding, realSni: String? = null): StageProbeResult =
        withContext(Dispatchers.IO) {
            fun result(rejected: String?, stages: List<StageOutcome>) =
                StageProbeResult(endpointId, binding.kind.name, binding.host, binding.port, rejected, stages)
            if (binding.kind != TransportKind.TLS_TCP) return@withContext result("transport not probed", emptyList())
            if (!ProbeTargets.isPublicGateway(binding.host)) return@withContext result("target is not a public IPv4 literal", emptyList())

            val started = nowMs()
            fun remaining() = TOTAL_BUDGET_MS - (nowMs() - started)
            val stages = mutableListOf<StageOutcome>()

            // Stage 1 keeps its connection and sends the first ClientHello on it.
            val t0 = nowMs()
            var connection: StageConnection? = try {
                connector.open(binding.host, binding.port, CONNECT_TIMEOUT_MS).also {
                    stages += StageOutcome(StageName.TCP_CONNECT, StageResult.OK, nowMs() - t0)
                }
            } catch (e: Exception) {
                stages += StageOutcome(StageName.TCP_CONNECT, classifyStageFailure(e), nowMs() - t0, errorType = e.javaClass.simpleName)
                null
            }
            if (connection == null) return@withContext result(null, stages)

            val plan = listOf(
                StageName.TLS_NO_SNI to null,
                StageName.TLS_NEUTRAL_SNI to NEUTRAL_SNI,
                StageName.TLS_REAL_SNI to realSni,
            )
            for ((index, step) in plan.withIndex()) {
                val (stage, sni) = step
                if (stage == StageName.TLS_REAL_SNI && sni == null) {
                    stages += StageOutcome(stage, StageResult.SKIPPED, 0, note = "no SNI known from the signed profile")
                    continue
                }
                if (remaining() < MIN_STAGE_BUDGET_MS) {
                    connection?.close()
                    stages += StageOutcome(stage, StageResult.SKIPPED, 0, note = "time budget")
                    connection = null
                    continue
                }
                if (index > 0) pause(PAUSE_MS) // no burst between stages
                if (connection == null) {
                    val c0 = nowMs()
                    connection = try {
                        connector.open(binding.host, binding.port, CONNECT_TIMEOUT_MS)
                    } catch (e: Exception) {
                        stages += StageOutcome(stage, classifyStageFailure(e), nowMs() - c0, errorType = e.javaClass.simpleName, note = "reconnect")
                        null
                    }
                    if (connection == null) continue
                }
                stages += sendHelloAndReadHeader(connection!!, stage, sni)
                connection!!.close()
                connection = null
            }
            connection?.close()
            result(null, stages)
        }

    private fun sendHelloAndReadHeader(connection: StageConnection, stage: StageName, sni: String?): StageOutcome {
        val t0 = nowMs()
        return try {
            connection.send(StageClientHello.build(sni, randomBytes(32), randomBytes(32)))
            val header = ByteArrayBuilder()
            val deadline = t0 + READ_TIMEOUT_MS
            while (header.size < 5) {
                val left = (deadline - nowMs()).toInt()
                if (left <= 0) throw SocketTimeoutException()
                val chunk = connection.read(5 - header.size, left)
                if (chunk.isEmpty()) break
                header.write(chunk)
            }
            val elapsed = nowMs() - t0
            val b = header.toByteArray()
            when {
                b.isEmpty() -> StageOutcome(stage, StageResult.CLOSE, elapsed)
                b[0].toInt() == 0x16 -> StageOutcome(stage, StageResult.HANDSHAKE, elapsed, recordType = 0x16, recordVersion = version(b))
                b[0].toInt() == 0x15 -> StageOutcome(stage, StageResult.ALERT, elapsed, recordType = 0x15, recordVersion = version(b))
                else -> StageOutcome(stage, StageResult.NOT_TLS, elapsed, recordType = b[0].toInt() and 0xFF)
            }
        } catch (e: Exception) {
            StageOutcome(stage, classifyStageFailure(e), nowMs() - t0, errorType = e.javaClass.simpleName)
        }
    }

    private fun version(header: ByteArray): String? =
        if (header.size >= 3) "${header[1].toInt() and 0xFF}.${header[2].toInt() and 0xFF}" else null

    private class ByteArrayBuilder {
        private val out = java.io.ByteArrayOutputStream()
        val size: Int get() = out.size()
        fun write(b: ByteArray) = out.write(b)
        fun toByteArray(): ByteArray = out.toByteArray()
    }

    companion object {
        const val NEUTRAL_SNI = "www.example.org"
        const val CONNECT_TIMEOUT_MS = 5_000
        const val READ_TIMEOUT_MS = 3_000L
        const val TOTAL_BUDGET_MS = 15_000L
        const val MIN_STAGE_BUDGET_MS = 4_000L
        const val PAUSE_MS = 1_000L
    }
}
