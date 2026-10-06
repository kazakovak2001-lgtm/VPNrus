package net.pocvpn.client.diagnostics.fieldtest

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Field test - "what exactly is blocked on this network, and how?"
 *
 * For each target domain (VPN OFF) the same questions censorship
 * measurement projects ask, each answered by an independent probe:
 *  - DNS: system resolver vs DNS-over-HTTPS (Cloudflare 1.1.1.1, Google
 *    8.8.8.8 JSON API) -> blocked or tampered lookups;
 *  - TCP to the DoH-resolved address -> IP blocking (timeout = drop,
 *    refused/reset = active reset);
 *  - TLS handshake to that address with the REAL SNI vs a NEUTRAL SNI ->
 *    SNI-based filtering;
 *  - HTTPS fetch -> works / freezes after a few KB (throttling);
 *  - plain HTTP over a raw socket -> ISP block page / redirect;
 * plus network-wide checks: UDP/53 to foreign resolvers, DoH reachability.
 *
 * Measurement only. A verdict is a label for what this device observed at
 * this time on this network - never a claim about the operator in general.
 * Probes never send credentials and never contact our gateways with a
 * blocked SNI.
 */

data class CensorshipTarget(val domain: String, val category: String)

object CensorshipTargets {
    val ALL = listOf(
        CensorshipTarget("www.youtube.com", "foreign-commonly-blocked"),
        CensorshipTarget("telegram.org", "foreign-commonly-blocked"),
        CensorshipTarget("www.instagram.com", "foreign-commonly-blocked"),
        CensorshipTarget("www.facebook.com", "foreign-commonly-blocked"),
        CensorshipTarget("x.com", "foreign-commonly-blocked"),
        CensorshipTarget("discord.com", "foreign-commonly-blocked"),
        CensorshipTarget("signal.org", "foreign-commonly-blocked"),
        CensorshipTarget("www.linkedin.com", "foreign-commonly-blocked"),
        CensorshipTarget("www.bbc.com", "registry-blocked-classic"),
        CensorshipTarget("www.google.com", "foreign-control"),
        CensorshipTarget("www.cloudflare.com", "foreign-control"),
        CensorshipTarget("www.wikipedia.org", "foreign-control"),
        CensorshipTarget("github.com", "foreign-control"),
        CensorshipTarget("ya.ru", "domestic-control"),
        CensorshipTarget("vk.com", "domestic-control"),
        CensorshipTarget("www.gosuslugi.ru", "domestic-control"),
        CensorshipTarget("control.aknova.pp.ua", "nova-infrastructure"),
        CensorshipTarget("edge-sthlm.aknova.pp.ua", "nova-infrastructure"),
    )
    const val NEUTRAL_SNI = "www.example.org"
}

data class TlsProbeResult(val sni: String, val ok: Boolean, val elapsedMs: Long, val error: String?)

data class PlainHttpResult(
    val ok: Boolean,
    val statusLine: String?,
    val location: String?,
    val bodyBytes: Int,
    val blockPageHint: Boolean,
    val error: String?,
)

data class TargetCensorshipResult(
    val target: CensorshipTarget,
    val systemDns: DnsProbeResult,
    val dohAddresses: List<String>,
    val dohError: String?,
    val tcp: TcpProbeResult?,
    val tlsRealSni: TlsProbeResult?,
    val tlsNeutralSni: TlsProbeResult?,
    val https: HttpProbeResult?,
    val plainHttp: PlainHttpResult?,
    val verdicts: List<String>,
)

data class CensorshipReport(
    val targets: List<TargetCensorshipResult>,
    val udpDns: Map<String, Boolean>,
    val dohReachable: Map<String, Boolean>,
    val networkVerdicts: List<String>,
)

// --- pure classification -----------------------------------------------------

private val PRIVATE_V4 = listOf(
    Regex("""^10\."""), Regex("""^127\."""), Regex("""^0\."""), Regex("""^192\.168\."""),
    Regex("""^172\.(1[6-9]|2\d|3[01])\."""), Regex("""^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\."""), Regex("""^169\.254\."""),
)

internal fun isBogon(address: String): Boolean = PRIVATE_V4.any { it.containsMatchIn(address) } || address == "::" || address == "::1"

private val BLOCK_PAGE_MARKERS = listOf(
    "rkn.gov.ru", "eais.rkn", "zapret", "blocklist", "blocked", "доступ ограничен", "доступ к ресурсу ограничен",
    "заблокирован", "warning.rt.ru", "blackhole", "restricted",
)

internal fun looksLikeBlockPage(domain: String, statusLine: String?, location: String?, body: String): Boolean {
    val lower = body.lowercase()
    if (BLOCK_PAGE_MARKERS.any { it in lower }) return true
    val loc = location?.lowercase() ?: return false
    if (BLOCK_PAGE_MARKERS.any { it in loc }) return true
    // A redirect to a different site (not the https upgrade of the same host) is suspicious.
    val locHost = Regex("""^https?://([^/:]+)""").find(loc)?.groupValues?.get(1) ?: return false
    val base = domain.removePrefix("www.").lowercase()
    return statusLine?.contains(" 30") == true && !locHost.endsWith(base)
}

internal fun classifyTarget(
    systemDns: DnsProbeResult,
    dohAddresses: List<String>,
    tcp: TcpProbeResult?,
    tlsReal: TlsProbeResult?,
    tlsNeutral: TlsProbeResult?,
    https: HttpProbeResult?,
    plainHttp: PlainHttpResult?,
): List<String> {
    val v = mutableListOf<String>()
    val dohOk = dohAddresses.isNotEmpty()
    when {
        !systemDns.ok && dohOk -> v += "DNS_BLOCKED"
        systemDns.ok && systemDns.addresses.any(::isBogon) -> v += "DNS_TAMPERED_BOGON"
        systemDns.ok && dohOk && systemDns.addresses.intersect(dohAddresses.toSet()).isEmpty() -> v += "DNS_DIFFERS_FROM_DOH"
    }
    if (tcp != null && !tcp.ok) {
        v += if (tcp.error?.contains("Timeout", ignoreCase = true) == true || tcp.error?.contains("timed out", ignoreCase = true) == true) {
            "IP_BLOCKED_DROP"
        } else {
            "IP_BLOCKED_RESET"
        }
    }
    if (tcp?.ok == true && tlsReal != null && !tlsReal.ok) {
        v += if (tlsNeutral?.ok == true) "SNI_FILTERED" else "TLS_BLOCKED"
    }
    if (https != null) {
        when {
            https.stalledAtBytes?.let { it in STALL_SUSPECT_RANGE } == true -> v += "THROTTLED_STALL"
            !https.ok && https.httpStatus == null && tlsReal?.ok == true -> v += "HTTPS_INTERFERENCE"
        }
    }
    if (plainHttp?.blockPageHint == true) v += "HTTP_BLOCK_PAGE"
    if (v.isEmpty()) {
        v += if (https?.httpStatus != null || https?.ok == true) "OK" else if (!dohOk && !systemDns.ok) "UNRESOLVABLE" else "UNREACHABLE_UNKNOWN"
    }
    return v
}

internal fun classifyNetwork(
    targets: List<TargetCensorshipResult>,
    udpDns: Map<String, Boolean>,
    dohReachable: Map<String, Boolean>,
): List<String> {
    val v = mutableListOf<String>()
    fun reachable(t: TargetCensorshipResult) = "OK" in t.verdicts || t.https?.httpStatus != null
    val domestic = targets.filter { it.target.category == "domestic-control" }
    val foreignControl = targets.filter { it.target.category == "foreign-control" }
    val blockedSet = targets.filter { it.target.category == "foreign-commonly-blocked" || it.target.category == "registry-blocked-classic" }
    if (domestic.isNotEmpty() && domestic.all(::reachable) && foreignControl.isNotEmpty() && foreignControl.none(::reachable)) {
        v += "WHITELIST_MODE_SUSPECTED (domestic sites reachable, foreign control sites not)"
    }
    if (domestic.isNotEmpty() && domestic.none(::reachable)) v += "NO_WORKING_INTERNET_OR_TOTAL_SHUTDOWN"
    val blockedCount = blockedSet.count { !reachable(it) || it.verdicts.any { x -> x != "OK" } }
    if (blockedSet.isNotEmpty()) v += "COMMONLY_BLOCKED_SERVICES_AFFECTED $blockedCount/${blockedSet.size}"
    val mechanisms = targets.flatMap { it.verdicts }.filter { it != "OK" }.groupingBy { it }.eachCount()
    if (mechanisms.isNotEmpty()) v += "MECHANISMS " + mechanisms.entries.sortedByDescending { it.value }.joinToString(", ") { "${it.key}x${it.value}" }
    if (udpDns.isNotEmpty() && udpDns.values.none { it }) v += "UDP53_TO_FOREIGN_RESOLVERS_BLOCKED"
    if (dohReachable.isNotEmpty() && dohReachable.values.none { it }) v += "DOH_BLOCKED"
    val nova = targets.filter { it.target.category == "nova-infrastructure" }
    nova.filter { !reachable(it) }.forEach { v += "NOVA_HOST_UNREACHABLE ${it.target.domain} (${it.verdicts.joinToString("+")})" }
    return v
}

// --- probes ------------------------------------------------------------------

object CensorshipProbe {

    suspend fun run(onLine: (String) -> Unit = {}): CensorshipReport = coroutineScope {
        val dohOk = mutableMapOf<String, Boolean>()
        dohOk["cloudflare-1.1.1.1"] = doh("www.google.com", useGoogle = false).isNotEmpty()
        dohOk["google-8.8.8.8"] = doh("www.google.com", useGoogle = true).isNotEmpty()
        val udp = mapOf(
            "8.8.8.8:53" to udpDnsWorks("8.8.8.8"),
            "1.1.1.1:53" to udpDnsWorks("1.1.1.1"),
            "77.88.8.8:53 (Yandex)" to udpDnsWorks("77.88.8.8"),
        )
        onLine("  DoH: $dohOk, UDP/53: $udp")
        val gate = Semaphore(4)
        val results = CensorshipTargets.ALL.map { t ->
            async { gate.withPermit { probeTarget(t).also { r -> onLine("  ${t.domain}: ${r.verdicts.joinToString("+")}") } } }
        }.awaitAll()
        CensorshipReport(results, udp, dohOk, classifyNetwork(results, udp, dohOk))
    }

    private suspend fun probeTarget(target: CensorshipTarget): TargetCensorshipResult {
        val sys = FieldProbes.dns(target.domain, null)
        var dohError: String? = null
        val dohAddrs = try {
            doh(target.domain, useGoogle = false).ifEmpty { doh(target.domain, useGoogle = true) }
        } catch (e: Exception) {
            dohError = describeError(e)
            emptyList()
        }
        val ip = dohAddrs.firstOrNull() ?: sys.addresses.firstOrNull { !isBogon(it) && !it.contains(':') }
        val tcp = ip?.let { FieldProbes.tcp("${target.domain} tcp/443", it, 443, null) }
        val tlsReal = if (tcp?.ok == true) tls(ip, target.domain) else null
        val tlsNeutral = if (tcp?.ok == true && tlsReal?.ok == false) tls(ip, CensorshipTargets.NEUTRAL_SNI) else null
        val https = FieldProbes.https("${target.domain} https", "https://${target.domain}/", null, maxBytes = 96 * 1024, stallTimeoutMs = 6_000, totalBudgetMs = 15_000)
        val plain = plainHttp(target.domain)
        return TargetCensorshipResult(
            target, sys, dohAddrs, dohError, tcp, tlsReal, tlsNeutral, https, plain,
            classifyTarget(sys, dohAddrs, tcp, tlsReal, tlsNeutral, https, plain),
        )
    }

    /** DNS-over-HTTPS JSON API; IPv4 answers only. Empty list on any failure. */
    internal suspend fun doh(name: String, useGoogle: Boolean): List<String> = withContext(Dispatchers.IO) {
        val url = if (useGoogle) "https://8.8.8.8/resolve?name=$name&type=A" else "https://1.1.1.1/dns-query?name=$name&type=A"
        try {
            val c = URL(url).openConnection() as HttpsURLConnection
            c.connectTimeout = 6_000
            c.readTimeout = 6_000
            c.setRequestProperty("accept", "application/dns-json")
            try {
                if (c.responseCode != 200) return@withContext emptyList()
                val body = c.inputStream.bufferedReader().readText()
                val answers = JSONObject(body).optJSONArray("Answer") ?: JSONArray()
                (0 until answers.length()).mapNotNull { i -> answers.optJSONObject(i)?.takeIf { it.optInt("type") == 1 }?.optString("data") }
            } finally {
                c.disconnect()
            }
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** TLS handshake only (chain validated by the platform, no hostname check, no request sent). */
    internal suspend fun tls(ip: String, sni: String, timeoutMs: Int = 8_000): TlsProbeResult = withContext(Dispatchers.IO) {
        val start = System.nanoTime()
        try {
            Socket().use { raw ->
                raw.connect(InetSocketAddress(ip, 443), timeoutMs)
                raw.soTimeout = timeoutMs
                val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, sni, 443, false) as SSLSocket
                ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(sni)) }
                ssl.startHandshake()
                ssl.close()
            }
            TlsProbeResult(sni, true, (System.nanoTime() - start) / 1_000_000, null)
        } catch (e: Exception) {
            TlsProbeResult(sni, false, (System.nanoTime() - start) / 1_000_000, describeError(e))
        }
    }

    /** Plain HTTP/1.1 GET over a raw socket (the app's cleartext policy stays untouched). */
    internal suspend fun plainHttp(domain: String, timeoutMs: Int = 8_000): PlainHttpResult = withContext(Dispatchers.IO) {
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(domain, 80), timeoutMs)
                s.soTimeout = timeoutMs
                s.getOutputStream().write("GET / HTTP/1.1\r\nHost: $domain\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".toByteArray())
                val buf = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(4096)
                val input = s.getInputStream()
                try {
                    while (buf.size() < 16 * 1024) {
                        val n = input.read(chunk)
                        if (n < 0) break
                        buf.write(chunk, 0, n)
                    }
                } catch (_: SocketTimeoutException) {
                }
                val text = buf.toString(Charsets.UTF_8.name())
                val head = text.substringBefore("\r\n\r\n")
                val statusLine = head.lineSequence().firstOrNull()?.trim()
                val location = head.lineSequence().firstOrNull { it.startsWith("Location:", ignoreCase = true) }?.substringAfter(':')?.trim()
                PlainHttpResult(
                    ok = statusLine != null, statusLine = statusLine, location = location, bodyBytes = buf.size(),
                    blockPageHint = looksLikeBlockPage(domain, statusLine, location, text), error = null,
                )
            }
        } catch (e: Exception) {
            PlainHttpResult(false, null, null, 0, false, describeError(e))
        }
    }

    /** One A query for example.com over UDP/53 to [server]; true when any answer arrives. */
    internal suspend fun udpDnsWorks(server: String): Boolean = withContext(Dispatchers.IO) {
        try {
            DatagramSocket().use { socket ->
                socket.soTimeout = 3_000
                val query = byteArrayOf(
                    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                    3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0, 0x00, 0x01, 0x00, 0x01,
                )
                socket.send(DatagramPacket(query, query.size, InetAddress.getByName(server), 53))
                val buf = ByteArray(512)
                socket.receive(DatagramPacket(buf, buf.size))
                buf[0] == 0x12.toByte() && buf[1] == 0x34.toByte()
            }
        } catch (e: Exception) {
            false
        }
    }
}

// --- JSON --------------------------------------------------------------------

fun CensorshipReport.toJson(): JSONObject = JSONObject()
    .put("networkVerdicts", JSONArray(networkVerdicts))
    .put("udpDns", JSONObject().apply { udpDns.forEach { (k, v) -> put(k, v) } })
    .put("dohReachable", JSONObject().apply { dohReachable.forEach { (k, v) -> put(k, v) } })
    .put("targets", JSONArray().apply { targets.forEach { put(it.toJson()) } })

internal fun TargetCensorshipResult.toJson(): JSONObject = JSONObject()
    .put("domain", target.domain)
    .put("category", target.category)
    .put("verdicts", JSONArray(verdicts))
    .put("systemDns", systemDns.toJson())
    .put("dohAddresses", JSONArray(dohAddresses))
    .put("dohError", dohError ?: JSONObject.NULL)
    .put("tcp", tcp?.toJson() ?: JSONObject.NULL)
    .put("tlsRealSni", tlsRealSni?.let { JSONObject().put("sni", it.sni).put("ok", it.ok).put("elapsedMs", it.elapsedMs).put("error", it.error ?: JSONObject.NULL) } ?: JSONObject.NULL)
    .put("tlsNeutralSni", tlsNeutralSni?.let { JSONObject().put("sni", it.sni).put("ok", it.ok).put("elapsedMs", it.elapsedMs).put("error", it.error ?: JSONObject.NULL) } ?: JSONObject.NULL)
    .put("https", https?.toJson() ?: JSONObject.NULL)
    .put("plainHttp", plainHttp?.let {
        JSONObject().put("ok", it.ok).put("statusLine", it.statusLine ?: JSONObject.NULL).put("location", it.location ?: JSONObject.NULL)
            .put("bodyBytes", it.bodyBytes).put("blockPageHint", it.blockPageHint).put("error", it.error ?: JSONObject.NULL)
    } ?: JSONObject.NULL)

internal fun CensorshipReport.summaryLines(): List<String> =
    listOf("-- Censorship analysis (VPN off) --") +
        networkVerdicts.map { "  NETWORK: $it" } +
        targets.map { "  ${it.target.domain} [${it.target.category}]: ${it.verdicts.joinToString("+")}" }
