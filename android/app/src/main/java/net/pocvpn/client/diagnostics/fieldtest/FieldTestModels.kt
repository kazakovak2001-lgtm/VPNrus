package net.pocvpn.client.diagnostics.fieldtest

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.json.JSONArray
import org.json.JSONObject

/**
 * One field-test attempt: a gateway (null = Auto gateway selection) and a
 * transport (null = Smart Connect transport choice). Executed through the
 * app's normal connect() path with the existing debug transport pin - the
 * field test never builds a second connection path.
 */
data class FieldAttemptTarget(
    val gateway: ProductionGatewayId?,
    val transport: TransportKind?,
    /** Non-null: an Auto connect restricted to relays entering via this ingress endpoint (DebugPathOverride). */
    val relayIngress: String? = null,
) {
    val label: String
        get() = when {
            relayIngress != null -> "RELAY via $relayIngress"
            else -> "${gateway?.name ?: "AUTO"} / ${transport?.name ?: "SMART_CONNECT"}"
        }
}

enum class FieldRunOutcome {
    /** Connected, exit IP matched, small probes AND the bulk download completed. */
    DATA_PLANE_OK,
    /** Connected; small probes worked but the bulk download did not complete (slow/partial). */
    DATA_PLANE_DEGRADED,
    /** Connected, then a flow froze after a few KB (8-64 KB) - the throttling pattern to look for. */
    DATA_PLANE_STALL_SUSPECTED,
    /** Tunnel reported Connected but no in-tunnel probe got a response. */
    CONNECTED_NO_DATA,
    /** In-tunnel traffic exited from an address that is not this gateway. */
    EXIT_MISMATCH,
    CONNECT_FAILED,
    HANDSHAKE_FAILED,
    CONNECT_TIMEOUT,
    /** The app refused the attempt up front (no profile/credential/binary/binding for it). */
    UNAVAILABLE,
    SKIPPED,
}

data class FieldTransportRun(
    val target: FieldAttemptTarget,
    val startedAtEpochMillis: Long,
    val outcome: FieldRunOutcome,
    val skipReason: String? = null,
    val connectMs: Long? = null,
    val terminalState: String? = null,
    val errorMessage: String? = null,
    val activeTransport: String? = null,
    val sessionHealth: String? = null,
    val expectedExitIps: Set<String> = emptySet(),
    val exitIp: String? = null,
    val exitColo: String? = null,
    val exitLoc: String? = null,
    val dns: DnsProbeResult? = null,
    val probes: List<HttpProbeResult> = emptyList(),
    val throughput: HttpProbeResult? = null,
    val stability: List<HttpProbeResult> = emptyList(),
    val transportScoresBefore: Map<String, Int> = emptyMap(),
    val diagnosticSession: JSONObject? = null,
    val disconnectMs: Long? = null,
    val notes: List<String> = emptyList(),
    /** In-tunnel DNS/IPv6 leak check (LeakChecks.inTunnel). */
    val leaks: JSONObject? = null,
)

/** Byte range in which a freeze is reported as the suspected throttling pattern. */
internal val STALL_SUSPECT_RANGE = 8L * 1024..64L * 1024

/**
 * Pure classification of one connected-or-not attempt - unit-tested
 * (FieldTestClassificationTest). Never upgrades a weaker observation: a
 * stall or exit mismatch always wins over "probes answered".
 */
internal fun classifyRun(
    connected: Boolean,
    terminalState: String?,
    errorMessage: String?,
    timedOut: Boolean,
    probes: List<HttpProbeResult>,
    throughput: HttpProbeResult?,
    stability: List<HttpProbeResult>,
    exitIp: String?,
    expectedExitIps: Set<String>,
): FieldRunOutcome {
    if (!connected) {
        val text = listOfNotNull(terminalState, errorMessage).joinToString(" ").lowercase()
        return when {
            UNAVAILABLE_MARKERS.any { it in text } -> FieldRunOutcome.UNAVAILABLE
            "handshakefailed" in text.replace(" ", "") -> FieldRunOutcome.HANDSHAKE_FAILED
            timedOut -> FieldRunOutcome.CONNECT_TIMEOUT
            else -> FieldRunOutcome.CONNECT_FAILED
        }
    }
    val all = probes + stability + listOfNotNull(throughput)
    if (all.any { r -> r.stalledAtBytes?.let { it in STALL_SUSPECT_RANGE } == true }) {
        return FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED
    }
    if (exitIp != null && expectedExitIps.isNotEmpty() && exitIp !in expectedExitIps) {
        return FieldRunOutcome.EXIT_MISMATCH
    }
    val anyAnswered = probes.any { it.httpStatus != null }
    if (!anyAnswered) return FieldRunOutcome.CONNECTED_NO_DATA
    return if (throughput?.ok == true) FieldRunOutcome.DATA_PLANE_OK else FieldRunOutcome.DATA_PLANE_DEGRADED
}

private val UNAVAILABLE_MARKERS = listOf(
    "nocandidateavailable", "no candidate", "not available", "unavailable", "not_implemented", "not implemented",
    "not provisioned", "no profile", "not eligible", "unsupportedtransportselected",
)

data class FieldDirectProbes(
    val dns: List<DnsProbeResult>,
    val http: List<HttpProbeResult>,
    val tcp: List<TcpProbeResult>,
)

data class FieldTestReport(
    val startedAtEpochMillis: Long,
    val finishedAtEpochMillis: Long,
    val cancelled: Boolean,
    val abortReason: String?,
    val app: JSONObject,
    val device: JSONObject,
    val networkContextBefore: JSONObject,
    val networkContextAfter: JSONObject?,
    val appStateBefore: JSONObject,
    val appStateAfter: JSONObject?,
    val direct: FieldDirectProbes?,
    val runs: List<FieldTransportRun>,
    val supportBundle: JSONObject?,
    val mode: FieldTestMode = FieldTestMode.FULL,
    val censorship: CensorshipReport? = null,
    val apiChecks: JSONArray? = null,
    val manifestRefresh: String? = null,
    val directResolver: DnsProbeResult? = null,
    val monitor: JSONObject? = null,
    val exitReasons: JSONArray? = null,
    val crashes: JSONArray? = null,
    val logs: List<String> = emptyList(),
) {
    companion object {
        const val SCHEMA = "nova-field-test"
        const val SCHEMA_VERSION = 1
    }
}

// --- human-readable summary (pure) -----------------------------------------

internal fun FieldTestReport.summaryLines(): List<String> {
    val lines = mutableListOf<String>()
    lines += "Nova field test ($mode) - ${if (cancelled) "CANCELLED" else if (abortReason != null) "ABORTED: $abortReason" else "COMPLETE"}"
    lines += "Duration: ${(finishedAtEpochMillis - startedAtEpochMillis) / 1000}s, runs: ${runs.size}"
    networkContextBefore.optString("summary").takeIf { it.isNotBlank() }?.let { lines += "Network: $it" }
    direct?.let { d ->
        lines += "-- Direct (outside VPN) --"
        d.http.forEach { lines += "  ${it.label}: ${httpVerdict(it)}" }
        d.tcp.forEach { lines += "  ${it.label}: ${if (it.ok) "TCP OK ${it.elapsedMs}ms" else "TCP FAIL (${it.error})"}" }
        d.dns.filter { !it.ok }.forEach { lines += "  DNS ${it.host}: FAIL (${it.error})" }
    }
    censorship?.let { lines += it.summaryLines() }
    apiChecks?.let { arr ->
        lines += "-- Activation/profile API (VPN off) --"
        for (i in 0 until arr.length()) {
            val o = arr.getJSONObject(i)
            lines += "  ${o.optString("origin")}${o.optString("path")}: ${o.optString("verdict")} (${o.opt("httpStatus")})"
        }
    }
    manifestRefresh?.let { lines += "Manifest refresh: $it" }
    directResolver?.let { lines += "DNS resolver (VPN off): ${it.addresses.joinToString(",").ifBlank { it.error.orEmpty() }}" }
    monitor?.let { m ->
        lines += "-- Monitor --"
        lines += "  connected ${m.optLong("connectedPercent")}% of ${m.optLong("durationMs") / 1000}s, probes ${m.optString("probeSuccess")}, reconnects ${m.optInt("reconnects")}, events ${m.optJSONArray("events")?.length() ?: 0}"
    }
    exitReasons?.let { arr ->
        val recent = (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }.filter { it.has("reason") }.take(5)
        if (recent.isNotEmpty()) lines += "Recent process exits: " + recent.joinToString("; ") { "${it.optString("reason")} status=${it.opt("status")}" }
    }
    crashes?.let { if (it.length() > 0) lines += "Recorded crashes: ${it.length()}" }
    if (runs.isNotEmpty()) lines += "-- VPN runs --"
    runs.forEach { r ->
        val detail = when (r.outcome) {
            FieldRunOutcome.SKIPPED -> r.skipReason.orEmpty()
            FieldRunOutcome.UNAVAILABLE, FieldRunOutcome.CONNECT_FAILED, FieldRunOutcome.HANDSHAKE_FAILED,
            FieldRunOutcome.CONNECT_TIMEOUT -> listOfNotNull(r.terminalState, r.errorMessage).joinToString(" - ")
            else -> buildString {
                append("connect ${r.connectMs?.let { "${it}ms" } ?: "?"}")
                r.activeTransport?.let { append(", via $it") }
                r.exitIp?.let { append(", exit $it") }
                r.exitColo?.let { append(" ($it)") }
                r.throughput?.let { append(", bulk ${throughputText(it)}") }
                val stalls = (r.probes + r.stability + listOfNotNull(r.throughput)).mapNotNull { it.stalledAtBytes }
                if (stalls.isNotEmpty()) append(", STALL at ${stalls.joinToString("/")} B")
                r.leaks?.optString("verdict")?.let { append(", leaks $it") }
            }
        }
        lines += "  ${r.target.label}: ${r.outcome} - $detail"
    }
    if (runs.isNotEmpty()) {
        val working = runs.filter { it.outcome == FieldRunOutcome.DATA_PLANE_OK }.map { it.target.label }
        lines += "Working end-to-end: ${if (working.isEmpty()) "NONE" else working.joinToString(", ")}"
    }
    return lines
}

private fun httpVerdict(r: HttpProbeResult): String = when {
    r.ok -> "OK ${r.httpStatus} ${r.bytesRead}B ${r.elapsedMs}ms"
    r.stalledAtBytes != null -> "STALL at ${r.stalledAtBytes}B (status ${r.httpStatus})"
    r.httpStatus != null -> "PARTIAL ${r.httpStatus} ${r.bytesRead}B (${r.error})"
    else -> "FAIL (${r.error})"
}

private fun throughputText(r: HttpProbeResult): String {
    val kbps = if (r.elapsedMs > 0) r.bytesRead * 8 / r.elapsedMs else 0
    return "${r.bytesRead / 1024}KB/${r.elapsedMs}ms (~${kbps}kbit/s)${if (r.ok) "" else " INCOMPLETE"}"
}

// --- JSON (fixed key order, same discipline as SupportBundle.toJson) --------

fun FieldTestReport.toJson(): JSONObject {
    val root = JSONObject()
    root.put("schema", FieldTestReport.SCHEMA)
    root.put("schemaVersion", FieldTestReport.SCHEMA_VERSION)
    root.put("startedAtEpochMillis", startedAtEpochMillis)
    root.put("finishedAtEpochMillis", finishedAtEpochMillis)
    root.put("cancelled", cancelled)
    root.put("abortReason", abortReason ?: JSONObject.NULL)
    root.put("summary", JSONArray(summaryLines()))
    root.put("app", app)
    root.put("device", device)
    root.put("networkContextBefore", networkContextBefore)
    root.put("networkContextAfter", networkContextAfter ?: JSONObject.NULL)
    root.put("appStateBefore", appStateBefore)
    root.put("appStateAfter", appStateAfter ?: JSONObject.NULL)
    root.put("direct", direct?.toJson() ?: JSONObject.NULL)
    root.put("runs", JSONArray().apply { runs.forEach { put(it.toJson()) } })
    root.put("supportBundle", supportBundle ?: JSONObject.NULL)
    root.put("mode", mode.name)
    root.put("censorship", censorship?.toJson() ?: JSONObject.NULL)
    root.put("apiChecks", apiChecks ?: JSONObject.NULL)
    root.put("manifestRefresh", manifestRefresh ?: JSONObject.NULL)
    root.put("directResolver", directResolver?.toJson() ?: JSONObject.NULL)
    root.put("monitor", monitor ?: JSONObject.NULL)
    root.put("exitReasons", exitReasons ?: JSONObject.NULL)
    root.put("crashes", crashes ?: JSONObject.NULL)
    root.put("logs", JSONArray(logs))
    return root
}

internal fun FieldDirectProbes.toJson(): JSONObject = JSONObject()
    .put("dns", JSONArray().apply { dns.forEach { put(it.toJson()) } })
    .put("http", JSONArray().apply { http.forEach { put(it.toJson()) } })
    .put("tcp", JSONArray().apply { tcp.forEach { put(it.toJson()) } })

internal fun FieldTransportRun.toJson(): JSONObject = JSONObject()
    .put("label", target.label)
    .put("gateway", target.gateway?.name ?: "AUTO")
    .put("transport", target.transport?.name ?: "SMART_CONNECT")
    .put("relayIngress", target.relayIngress ?: JSONObject.NULL)
    .put("startedAtEpochMillis", startedAtEpochMillis)
    .put("outcome", outcome.name)
    .put("skipReason", skipReason ?: JSONObject.NULL)
    .put("connectMs", connectMs ?: JSONObject.NULL)
    .put("terminalState", terminalState ?: JSONObject.NULL)
    .put("errorMessage", errorMessage ?: JSONObject.NULL)
    .put("activeTransport", activeTransport ?: JSONObject.NULL)
    .put("sessionHealth", sessionHealth ?: JSONObject.NULL)
    .put("expectedExitIps", JSONArray(expectedExitIps.sorted()))
    .put("exitIp", exitIp ?: JSONObject.NULL)
    .put("exitColo", exitColo ?: JSONObject.NULL)
    .put("exitLoc", exitLoc ?: JSONObject.NULL)
    .put("dns", dns?.toJson() ?: JSONObject.NULL)
    .put("probes", JSONArray().apply { probes.forEach { put(it.toJson()) } })
    .put("throughput", throughput?.toJson() ?: JSONObject.NULL)
    .put("stability", JSONArray().apply { stability.forEach { put(it.toJson()) } })
    .put("transportScoresBefore", JSONObject().apply { transportScoresBefore.toSortedMap().forEach { (k, v) -> put(k, v) } })
    .put("diagnosticSession", diagnosticSession ?: JSONObject.NULL)
    .put("disconnectMs", disconnectMs ?: JSONObject.NULL)
    .put("notes", JSONArray(notes))
    .put("leaks", leaks ?: JSONObject.NULL)

internal fun DnsProbeResult.toJson(): JSONObject = JSONObject()
    .put("host", host).put("ok", ok).put("addresses", JSONArray(addresses))
    .put("elapsedMs", elapsedMs).put("error", error ?: JSONObject.NULL)

internal fun TcpProbeResult.toJson(): JSONObject = JSONObject()
    .put("label", label).put("host", host).put("port", port).put("ok", ok)
    .put("elapsedMs", elapsedMs).put("error", error ?: JSONObject.NULL)

internal fun HttpProbeResult.toJson(): JSONObject = JSONObject()
    .put("label", label).put("url", url).put("ok", ok)
    .put("httpStatus", httpStatus ?: JSONObject.NULL)
    .put("elapsedMs", elapsedMs)
    .put("timeToHeadersMs", timeToHeadersMs ?: JSONObject.NULL)
    .put("bytesRead", bytesRead)
    .put("stalledAtBytes", stalledAtBytes ?: JSONObject.NULL)
    .put("bodyComplete", bodyComplete)
    .put("error", error ?: JSONObject.NULL)
    .put("trace", JSONObject().apply { trace.toSortedMap().forEach { (k, v) -> put(k, v) } })
