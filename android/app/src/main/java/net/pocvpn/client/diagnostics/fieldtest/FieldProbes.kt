package net.pocvpn.client.diagnostics.fieldtest

import android.net.Network
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * Field-test probe primitives (Russia/restricted-network field validation).
 *
 * Measurement only: no credential, no request body, platform CA validation
 * only (no custom TrustManager - our gateways serve Let's Encrypt IP
 * certificates, see GatewayReachabilityProbe). Every probe is bounded by
 * explicit timeouts and never throws - a failure is a recorded result.
 *
 * [network] == null -> the process default network (used BEFORE the field
 * test connects anything, i.e. direct/outside-tunnel). A VPN [Network] binds
 * the socket/lookup to the tunnel explicitly, so an in-tunnel result can
 * never be a silent off-tunnel success (same rule as the B37 field-test
 * probes).
 */

/**
 * B54 Scope A - what kind of exception ended a probe, decided by exception
 * TYPE (never by message text). Null when the probe did not throw.
 */
enum class ProbeFailureKind {
    TIMEOUT,
    UNKNOWN_HOST,

    /** R1-S2 - a TLS-layer failure (certificate validation included); validation is never relaxed to avoid it. */
    TLS,

    /**
     * R1-S2 - the OS refused the connect with ENETUNREACH/EHOSTUNREACH,
     * read from the errno carried in the exception's cause chain. Never
     * inferred from message text; absent when the platform attaches no errno.
     */
    NO_ROUTE,
    OTHER,
}

/** The OS error numbers that mean "no route to the network/host", from the platform constants. */
private fun platformNoRouteErrnos(): Set<Int> =
    setOf(android.system.OsConstants.ENETUNREACH, android.system.OsConstants.EHOSTUNREACH)

private fun platformErrnoOf(t: Throwable): Int? = (t as? android.system.ErrnoException)?.errno

internal fun failureKindOf(
    e: Throwable,
    errnoOf: (Throwable) -> Int? = ::platformErrnoOf,
    noRouteErrnos: () -> Set<Int> = ::platformNoRouteErrnos,
): ProbeFailureKind = when {
    e is SocketTimeoutException -> ProbeFailureKind.TIMEOUT
    e is java.net.UnknownHostException -> ProbeFailureKind.UNKNOWN_HOST
    causeChain(e).any { it is javax.net.ssl.SSLException } -> ProbeFailureKind.TLS
    causeChain(e).any { t -> errnoOf(t)?.let { it in noRouteErrnos() } == true } -> ProbeFailureKind.NO_ROUTE
    else -> ProbeFailureKind.OTHER
}

/** [e] and its causes, bounded so a cyclic chain cannot loop. */
private fun causeChain(e: Throwable): List<Throwable> {
    val out = ArrayList<Throwable>(4)
    var cur: Throwable? = e
    while (cur != null && out.size < 6 && out.none { it === cur }) {
        out += cur
        cur = cur.cause
    }
    return out
}

data class DnsProbeResult(
    val host: String,
    val ok: Boolean,
    val addresses: List<String>,
    val elapsedMs: Long,
    val error: String?,
    val failureKind: ProbeFailureKind? = null,
)

data class TcpProbeResult(
    val label: String,
    val host: String,
    val port: Int,
    val ok: Boolean,
    val elapsedMs: Long,
    val error: String?,
)

data class HttpProbeResult(
    val label: String,
    val url: String,
    val ok: Boolean,
    val httpStatus: Int?,
    val elapsedMs: Long,
    /** Time until the response status line arrived (DNS + TCP + TLS + request). */
    val timeToHeadersMs: Long?,
    val bytesRead: Long,
    /** Non-null when the body stopped arriving for [stallTimeoutMs] before completion. */
    val stalledAtBytes: Long?,
    val bodyComplete: Boolean,
    val error: String?,
    /** Parsed key=value lines of a Cloudflare `/cdn-cgi/trace` body (filtered by the caller). */
    val trace: Map<String, String> = emptyMap(),
    val failureKind: ProbeFailureKind? = null,
    /**
     * First received body byte -> last received body byte (null when no body byte arrived or the
     * probe predates this field). Unlike [elapsedMs] it excludes DNS, connect, TLS and any final
     * stall wait, so it is the only window a transfer rate may be computed over.
     */
    val transferMs: Long? = null,
)

/** One short, non-secret description of a failure: exception class + first line of the message. */
// "failed to connect to host/1.2.3.4 (port 443) from /192.168.1.3 (port 43046)" -
// the device's own local address/port never goes into a report.
private val localEndpoint = Regex(""" from /\S+ \(port \d+\)""")

internal fun describeError(e: Throwable): String {
    val message = e.message?.lineSequence()?.firstOrNull()?.replace(localEndpoint, "")?.take(160)
    return if (message.isNullOrBlank()) e.javaClass.simpleName else "${e.javaClass.simpleName}: $message"
}

object FieldProbes {

    suspend fun dns(host: String, network: Network?): DnsProbeResult = withContext(Dispatchers.IO) {
        val start = System.nanoTime()
        try {
            val addresses = network?.getAllByName(host) ?: InetAddress.getAllByName(host)
            DnsProbeResult(host, true, addresses.mapNotNull { it.hostAddress }.distinct(), elapsedSince(start), null)
        } catch (e: Exception) {
            DnsProbeResult(host, false, emptyList(), elapsedSince(start), describeError(e), failureKindOf(e))
        }
    }

    suspend fun tcp(label: String, host: String, port: Int, network: Network?, timeoutMs: Int = 8_000): TcpProbeResult =
        withContext(Dispatchers.IO) {
            val start = System.nanoTime()
            val socket = try {
                network?.socketFactory?.createSocket() ?: Socket()
            } catch (e: IOException) {
                return@withContext TcpProbeResult(label, host, port, false, elapsedSince(start), describeError(e))
            }
            try {
                socket.connect(InetSocketAddress(host, port), timeoutMs)
                TcpProbeResult(label, host, port, true, elapsedSince(start), null)
            } catch (e: Exception) {
                TcpProbeResult(label, host, port, false, elapsedSince(start), describeError(e))
            } finally {
                try { socket.close() } catch (_: IOException) {}
            }
        }

    /**
     * GET [url], reading at most [maxBytes] of body. A read that sees no
     * byte for [stallTimeoutMs] records [HttpProbeResult.stalledAtBytes] -
     * the signal for "connection established, then frozen after N bytes"
     * (e.g. the publicly reported ~16 KB freeze of TLS flows to foreign
     * hosting). [totalBudgetMs] bounds the whole download.
     */
    suspend fun https(
        label: String,
        url: String,
        network: Network?,
        maxBytes: Long = 64 * 1024,
        connectTimeoutMs: Int = 10_000,
        stallTimeoutMs: Int = 8_000,
        totalBudgetMs: Long = 30_000,
        parseTrace: Boolean = false,
    ): HttpProbeResult = withContext(Dispatchers.IO) {
        val start = System.nanoTime()
        var connection: HttpsURLConnection? = null
        var bytes = 0L
        var status: Int? = null
        var headersMs: Long? = null
        var firstByteNanos: Long? = null
        var lastByteNanos: Long? = null
        val body = if (parseTrace) StringBuilder() else null
        try {
            val target = URL(url)
            connection = (network?.openConnection(target) ?: target.openConnection()) as HttpsURLConnection
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = connectTimeoutMs
            connection.readTimeout = stallTimeoutMs
            connection.setRequestProperty("Accept-Encoding", "identity")
            status = connection.responseCode
            headersMs = elapsedSince(start)
            val stream = if (status >= 400) connection.errorStream else connection.inputStream
            var stalledAt: Long? = null
            var complete = false
            if (stream == null) {
                complete = true
            } else {
                stream.use { input ->
                    val buffer = ByteArray(8 * 1024)
                    val deadline = start + totalBudgetMs * 1_000_000
                    while (true) {
                        if (System.nanoTime() > deadline) break
                        val n = try {
                            input.read(buffer)
                        } catch (e: SocketTimeoutException) {
                            stalledAt = bytes
                            break
                        }
                        if (n < 0) {
                            complete = true
                            break
                        }
                        if (body != null && body.length < 4_096) body.append(String(buffer, 0, n, Charsets.UTF_8))
                        val now = System.nanoTime()
                        if (firstByteNanos == null) firstByteNanos = now
                        lastByteNanos = now
                        bytes += n
                        if (bytes >= maxBytes) {
                            complete = true
                            break
                        }
                    }
                }
            }
            HttpProbeResult(
                label = label,
                url = url,
                ok = stalledAt == null && complete,
                httpStatus = status,
                elapsedMs = elapsedSince(start),
                timeToHeadersMs = headersMs,
                bytesRead = bytes,
                stalledAtBytes = stalledAt,
                bodyComplete = complete,
                error = if (stalledAt != null) "stalled after $stalledAt bytes" else if (!complete) "time budget exhausted" else null,
                trace = body?.let { parseTraceBody(it.toString()) }.orEmpty(),
                transferMs = firstByteNanos?.let { first -> lastByteNanos?.let { last -> (last - first) / 1_000_000 } },
            )
        } catch (e: Exception) {
            HttpProbeResult(
                label = label,
                url = url,
                ok = false,
                httpStatus = status,
                elapsedMs = elapsedSince(start),
                timeToHeadersMs = headersMs,
                bytesRead = bytes,
                stalledAtBytes = if (status != null && e is SocketTimeoutException) bytes else null,
                bodyComplete = false,
                error = describeError(e),
                failureKind = failureKindOf(e),
            )
        } finally {
            connection?.disconnect()
        }
    }

    private fun elapsedSince(startNanos: Long): Long = (System.nanoTime() - startNanos) / 1_000_000
}

/** Parses Cloudflare `/cdn-cgi/trace` (`key=value` per line). Pure. */
internal fun parseTraceBody(body: String): Map<String, String> =
    body.lineSequence()
        .mapNotNull { line -> line.indexOf('=').takeIf { it > 0 }?.let { line.substring(0, it).trim() to line.substring(it + 1).trim() } }
        .filter { (k, _) -> k.isNotEmpty() }
        .toMap()
