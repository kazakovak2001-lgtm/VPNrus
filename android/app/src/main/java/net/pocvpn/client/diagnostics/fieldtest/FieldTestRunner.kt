package net.pocvpn.client.diagnostics.fieldtest

import android.net.Network
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.ingressKind
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.json.JSONObject

/**
 * Everything the field test needs from the app, kept narrow so the runner
 * is testable with a fake. The production implementation (MainViewModel)
 * maps every call onto the EXISTING authorities: the debug transport pin
 * (debugSetTransportPreference), gateway selection (selectGateway /
 * setGatewayAutoMode), connect()/disconnect(), the trusted manifest and the
 * support-diagnostics recorder. No second connection path.
 */
interface FieldTestHost {
    val transportState: StateFlow<TransportState>
    val sessionHealth: StateFlow<VpnSessionHealth>
    val currentTransportKind: StateFlow<TransportKind?>
    fun vpnPermissionGranted(): Boolean
    fun provisionedGateways(): Set<ProductionGatewayId>
    fun trustedManifest(): EndpointManifest?
    fun endpointIdFor(gateway: ProductionGatewayId): String
    fun saveSelection(): Any
    fun restoreSelection(saved: Any)
    /** Applies gateway + transport pin for the NEXT connect(); returns a reason when it cannot. */
    fun applyTarget(target: FieldAttemptTarget): String?
    fun connect()
    fun disconnect()
    fun transportScores(): Map<TransportKind, Int>
    fun lastErrorText(): String?
    /** Attempt keys a forced relay run actually kept (null when no forced run happened). */
    fun lastForcedRelayKeys(): List<String>?
    /** Whether this device holds an activated profile for relay ingress [ingressId] (read-only). */
    suspend fun relayIngressActivation(ingressId: String): String = "unknown"
    fun latestDiagnosticSession(): JSONObject?
    fun appState(): JSONObject
    fun supportBundle(): JSONObject?
    fun networkContext(): JSONObject
    fun vpnNetwork(): Network?
    fun appInfo(): JSONObject
    fun deviceInfo(): JSONObject
    /** The app's own signed-manifest refresh from every origin (MultiOriginRefreshResult as text). */
    suspend fun refreshManifestOutcome(): String?
    fun exitReasons(): org.json.JSONArray
    fun crashes(): org.json.JSONArray
    suspend fun logs(): List<String>
    /**
     * Xray-family sessions exclude the Nova app from their own tunnel, so the
     * app cannot probe through them; the `:xray` process measures with the
     * Xray core itself (latency only). Null when it does not answer.
     */
    suspend fun measureViaXrayCore(urls: List<String>): List<net.pocvpn.client.vpn.xray.XrayProcessBridge.CoreMeasurement>?
    /** One-line description of the current default network (for monitor samples). */
    fun activeNetworkSummary(): String
}

enum class FieldTestMode {
    /** Everything, including every gateway x transport and relay run (15-30 min). */
    FULL,
    /** No VPN cycling: context, direct probes, censorship analysis, API, crashes, logs (2-4 min). */
    QUICK,
    /** Keep the user's normal connection up and observe it over time. */
    MONITOR,
}

data class FieldTestProgress(
    val running: Boolean,
    val phase: String,
    val step: Int,
    val totalSteps: Int,
    val log: List<String>,
    val report: FieldTestReport? = null,
)

/** Timing knobs - production defaults; tests shrink them. */
data class FieldTestTimings(
    val connectTimeoutMs: Long = 75_000,
    val healthGraceMs: Long = 20_000,
    val settleMs: Long = 2_000,
    val stabilityHoldMs: Long = 20_000,
    val disconnectTimeoutMs: Long = 20_000,
    val betweenRunsMs: Long = 3_000,
    val notStartedGraceMs: Long = 8_000,
)

/** Probe set - production targets; tests replace the probe functions, never these strings. */
object FieldTestTargets {
    const val CONNECTIVITY_204 = "https://connectivitycheck.gstatic.com/generate_204"
    const val CLOUDFLARE_TRACE = "https://www.cloudflare.com/cdn-cgi/trace"
    const val BULK_DIRECT = "https://speed.cloudflare.com/__down?bytes=262144"
    const val BULK_TUNNEL = "https://speed.cloudflare.com/__down?bytes=1048576"

    /** Outside-tunnel context: control, foreign services commonly blocked in RU, domestic controls. */
    val DIRECT_HTTP = listOf(
        "Google 204 (control)" to CONNECTIVITY_204,
        "YouTube" to "https://www.youtube.com/",
        "Telegram" to "https://telegram.org/",
        "Instagram" to "https://www.instagram.com/",
        "Yandex (domestic control)" to "https://ya.ru/",
        "VK (domestic control)" to "https://vk.com/",
    )
    val DIRECT_DNS = listOf(
        "control.aknova.pp.ua", "edge-sthlm.aknova.pp.ua", "www.google.com", "www.youtube.com",
        "telegram.org", "speed.cloudflare.com",
    )
    /** In-tunnel: does the tunnel carry real traffic, and does it unblock the blocked services? */
    val TUNNEL_HTTP = listOf(
        "Google 204" to CONNECTIVITY_204,
        "Telegram" to "https://telegram.org/",
        "YouTube" to "https://www.youtube.com/",
    )
    const val TUNNEL_DNS = "www.google.com"
    const val CONTROL_PLANE_HOST = "control.aknova.pp.ua"
}

/** Probe entry points, injectable for tests. */
class FieldProbeSet(
    val dns: suspend (String, Network?) -> DnsProbeResult = { h, n -> FieldProbes.dns(h, n) },
    val tcp: suspend (String, String, Int, Network?) -> TcpProbeResult = { l, h, p, n -> FieldProbes.tcp(l, h, p, n) },
    val https: suspend (label: String, url: String, network: Network?, maxBytes: Long, parseTrace: Boolean) -> HttpProbeResult =
        { l, u, n, m, t -> FieldProbes.https(l, u, n, maxBytes = m, parseTrace = t) },
    val censorship: suspend ((String) -> Unit) -> CensorshipReport = { onLine -> CensorshipProbe.run(onLine) },
    val api: suspend (List<String>) -> org.json.JSONArray = { origins -> ApiReachability.check(origins) },
    val leaks: suspend (Network?, List<String>) -> JSONObject = { n, direct -> LeakChecks.inTunnel(n, direct) },
)

/** UDP-only transport kinds: a TCP connect says nothing about them, the VPN run does. */
private val UDP_KINDS = setOf(TransportKind.AMNEZIA_WG, TransportKind.HYSTERIA2, TransportKind.QUIC)

/** Transports a full run tries per gateway, in this order (cheapest/oldest first). */
val FIELD_TEST_TRANSPORTS = listOf(
    TransportKind.AMNEZIA_WG,
    TransportKind.XRAY_REALITY,
    TransportKind.TLS_TCP,
    TransportKind.XRAY_XHTTP,
    TransportKind.SHADOWSOCKS_2022,
    TransportKind.HYSTERIA2,
)

/** Pure: API origins to check - every IP-literal host in the manifest, then the control-plane hostname. */
internal fun apiOrigins(manifest: EndpointManifest?): List<String> =
    (expectedExitIps(manifest, null).sorted() + FieldTestTargets.CONTROL_PLANE_HOST).distinct()

/**
 * Pure: the attempt list for a run. Every gateway x transport, then one run
 * per relay ingress the signed manifest declares (CDN-fronted XHTTP, DIRECT_IP
 * REALITY, ...), then Smart Connect.
 */
internal fun planAttempts(gateways: List<ProductionGatewayId>, relayIngresses: List<String> = emptyList()): List<FieldAttemptTarget> =
    gateways.flatMap { g -> FIELD_TEST_TRANSPORTS.map { FieldAttemptTarget(g, it) } } +
        relayIngresses.map { FieldAttemptTarget(null, null, relayIngress = it) } +
        FieldAttemptTarget(null, null)

/** Pure: ingress endpoints in [manifest] (role INGRESS or an ingress-kind binding), manifest order. */
internal fun relayIngressIds(manifest: EndpointManifest?): List<String> =
    manifest?.endpoints.orEmpty()
        .filter { e -> net.pocvpn.client.reachability.EndpointRole.INGRESS in e.roles || e.transports.any { it.ingressKind() != null } }
        .map { it.id.value }

/** Pure: IP-literal hosts of [endpointId]'s signed bindings (all endpoints when null). */
internal fun expectedExitIps(manifest: EndpointManifest?, endpointId: String?): Set<String> {
    val endpoints = manifest?.endpoints.orEmpty().filter { endpointId == null || it.id.value == endpointId }
    return endpoints.flatMap { e -> e.transports.map { it.host } }.filter { IPV4_LITERAL.matches(it) }.toSet()
}

private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
private const val POLL_MS = 250L
private const val NOT_STARTED = "NotStarted"
private val XRAY_FAMILY = setOf(TransportKind.XRAY_REALITY, TransportKind.TLS_TCP, TransportKind.XRAY_XHTTP)

/** Readable state names for reports (plain objects would print as Class@hash). */
internal fun TransportState.label(): String = when (this) {
    is TransportState.Error -> "Error(${message}${failureKind?.let { ", $it" } ?: ""})"
    is TransportState.Reconnecting -> "Reconnecting($attempt)"
    else -> this::class.simpleName ?: toString()
}

/** Public bridge for MainViewModel's app-state snapshot. */
object FieldStateLabels {
    fun TransportState.text(): String = label()
    fun VpnSessionHealth.text(): String = label()
}

internal fun VpnSessionHealth.label(): String = when (this) {
    is VpnSessionHealth.Failed -> "Failed($message)"
    is VpnSessionHealth.RelayHandshake -> "RelayHandshake($stage)"
    else -> this::class.simpleName ?: toString()
}
internal const val MONITOR_SAMPLE_MS = 30_000L
internal const val MONITOR_TICK_MS = 1_000L
internal const val MONITOR_BULK_EVERY = 10

class FieldTestRunner(
    private val host: FieldTestHost,
    private val probes: FieldProbeSet = FieldProbeSet(),
    private val timings: FieldTestTimings = FieldTestTimings(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val log = mutableListOf<String>()

    suspend fun run(onProgress: (FieldTestProgress) -> Unit): FieldTestReport = run(FieldTestMode.FULL, 0, onProgress)

    suspend fun run(mode: FieldTestMode, monitorDurationMs: Long, onProgress: (FieldTestProgress) -> Unit): FieldTestReport {
        val startedAt = clock()
        val manifest = host.trustedManifest()
        val attempts = if (mode == FieldTestMode.FULL) {
            planAttempts(ProductionGatewayId.entries.toList(), relayIngressIds(manifest))
        } else {
            emptyList()
        }
        val totalSteps = when (mode) {
            FieldTestMode.FULL -> attempts.size + 4
            FieldTestMode.QUICK -> 4
            FieldTestMode.MONITOR -> ((monitorDurationMs / MONITOR_SAMPLE_MS).toInt() + 2).coerceAtLeast(2)
        }
        var step = 0
        fun progress(phase: String, line: String? = null) {
            line?.let { log += it }
            onProgress(FieldTestProgress(true, phase, step, totalSteps, log.toList()))
        }

        val networkBefore = host.networkContext()
        val appBefore = host.appState()
        val saved = host.saveSelection()
        val wasConnected = host.transportState.value is TransportState.Connected
        val runs = mutableListOf<FieldTransportRun>()
        var direct: FieldDirectProbes? = null
        var censorship: CensorshipReport? = null
        var api: org.json.JSONArray? = null
        var manifestRefresh: String? = null
        var directResolver: DnsProbeResult? = null
        var monitor: JSONObject? = null
        var abort: String? = null
        var cancelled = false
        try {
            progress("Preparing", "Mode: $mode. Network: ${networkBefore.optString("summary")}")
            val needsVpn = mode != FieldTestMode.QUICK
            if (needsVpn && !host.vpnPermissionGranted()) {
                abort = "VPN permission not granted - connect once from the home screen first"
            } else if (mode == FieldTestMode.MONITOR) {
                monitor = monitorSession(monitorDurationMs) { line ->
                    step = (step + 1).coerceAtMost(totalSteps - 1)
                    progress("Monitoring", line)
                }
            } else {
                if (host.transportState.value !is TransportState.Disconnected) {
                    progress("Preparing", "Disconnecting the current session (direct probes must not use the tunnel)")
                    disconnectAndWait()
                }
                step++
                progress("Direct probes", "Direct (VPN off) probes...")
                direct = directProbes(manifest) { progress("Direct probes", it) }
                val resolver = probes.dns(LeakChecks.RESOLVER_WHOAMI, null)
                directResolver = resolver
                progress("Direct probes", "  DNS resolver (VPN off): ${resolver.addresses.joinToString(",").ifBlank { resolver.error.orEmpty() }}")
                step++
                progress("Censorship analysis", "What is blocked on this network, and how...")
                val c = probes.censorship { progress("Censorship analysis", it) }
                censorship = c
                c.networkVerdicts.forEach { progress("Censorship analysis", "  => $it") }
                step++
                progress("API checks", "Activation / profile API and manifest from this network...")
                val apiResult = probes.api(apiOrigins(manifest))
                api = apiResult
                for (i in 0 until apiResult.length()) {
                    val o = apiResult.getJSONObject(i)
                    progress("API checks", "  ${o.optString("origin")}${o.optString("path")}: ${o.optString("verdict")} ${o.opt("httpStatus")}")
                }
                manifestRefresh = host.refreshManifestOutcome()
                progress("API checks", "  manifest refresh: ${manifestRefresh ?: "-"}")
                attempts.forEach { target ->
                    step++
                    progress("VPN runs", "[$step/$totalSteps] ${target.label}")
                    val run = runOne(target, manifest, resolver.addresses)
                    runs += run
                    val leakText = run.leaks?.optString("verdict")?.let { " leaks=$it" } ?: ""
                    val why = run.errorMessage?.let { " ($it)" } ?: run.skipReason?.let { " ($it)" } ?: ""
                    progress("VPN runs", "  -> ${run.outcome}${run.exitIp?.let { " exit $it" } ?: ""}$leakText$why")
                    if (run.outcome != FieldRunOutcome.SKIPPED) delay(timings.betweenRunsMs)
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Cancel still yields a (partial) report - every finished measurement is evidence.
            cancelled = true
            log += "Cancelled by the user."
        } finally {
            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
                if (host.transportState.value !is TransportState.Disconnected) disconnectAndWait()
                host.restoreSelection(saved)
            }
        }
        val logs = kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { host.logs() }
        step = totalSteps
        val report = FieldTestReport(
            startedAtEpochMillis = startedAt,
            finishedAtEpochMillis = clock(),
            cancelled = cancelled,
            abortReason = abort,
            app = host.appInfo(),
            device = host.deviceInfo(),
            networkContextBefore = networkBefore,
            networkContextAfter = host.networkContext(),
            appStateBefore = appBefore,
            appStateAfter = host.appState(),
            direct = direct,
            runs = runs,
            supportBundle = host.supportBundle(),
            mode = mode,
            censorship = censorship,
            apiChecks = api,
            manifestRefresh = manifestRefresh,
            directResolver = directResolver,
            monitor = monitor,
            exitReasons = host.exitReasons(),
            crashes = host.crashes(),
            logs = logs,
        )
        abort?.let { log += "ABORTED: $it" }
        // QUICK during a normal session: give the user the connection back.
        if (mode == FieldTestMode.QUICK && wasConnected && !cancelled) {
            log += "Reconnecting the session that was active before the check."
            host.connect()
        }
        log += "Done."
        onProgress(FieldTestProgress(false, "Done", totalSteps, totalSteps, log.toList(), report))
        return report
    }

    /**
     * MONITOR: one normal connect with the user's own selection (nothing
     * pinned), then a small probe every MONITOR_SAMPLE_MS and a 256 KB
     * download every MONITOR_BULK_EVERY samples, recording every state,
     * health, transport and network change in between. The app's own
     * reconnect logic is observed, never replaced.
     */
    private suspend fun monitorSession(durationMs: Long, onLine: (String) -> Unit): JSONObject {
        val samples = org.json.JSONArray()
        val events = org.json.JSONArray()
        val start = clock()
        fun event(text: String) {
            events.put(JSONObject().put("tMs", clock() - start).put("event", text))
            onLine("  +${(clock() - start) / 1000}s $text")
        }
        if (host.transportState.value !is TransportState.Connected) {
            host.connect()
            event("connect requested (user selection)")
        }
        var lastState = ""
        var lastHealth = ""
        var lastTransport = ""
        var lastNetwork = ""
        var probesOk = 0
        var probesTotal = 0
        var connectedMs = 0L
        var reconnects = 0
        var sampleIndex = 0
        var nextSample = start
        var lastTick = start
        while (clock() - start < durationMs) {
            val now = clock()
            val state = host.transportState.value
            if (state is TransportState.Connected) connectedMs += now - lastTick
            lastTick = now
            val stateText = state.label()
            if (stateText != lastState) {
                if (state is TransportState.Reconnecting) reconnects++
                event("state $stateText")
                lastState = stateText
            }
            val healthText = host.sessionHealth.value.label()
            if (healthText != lastHealth) {
                event("health $healthText")
                lastHealth = healthText
            }
            val transportText = host.currentTransportKind.value?.name ?: "-"
            if (transportText != lastTransport) {
                event("transport $transportText")
                lastTransport = transportText
            }
            val networkText = host.activeNetworkSummary()
            if (networkText != lastNetwork) {
                event("network $networkText")
                lastNetwork = networkText
            }
            if (now >= nextSample) {
                nextSample = now + MONITOR_SAMPLE_MS
                val vpn = host.vpnNetwork()
                val connected = state is TransportState.Connected
                val probe = if (connected) probes.https("monitor 204", FieldTestTargets.CONNECTIVITY_204, vpn, 4 * 1024, false) else null
                val bulk = if (connected && sampleIndex % MONITOR_BULK_EVERY == 0) {
                    probes.https("monitor 256KB", FieldTestTargets.BULK_DIRECT, vpn, 262_144, false)
                } else {
                    null
                }
                if (probe != null) {
                    probesTotal++
                    if (probe.httpStatus != null) probesOk++
                }
                samples.put(
                    JSONObject().put("tMs", now - start).put("state", stateText).put("transport", transportText)
                        .put("probeOk", probe?.let { it.httpStatus != null } ?: JSONObject.NULL)
                        .put("probeMs", probe?.elapsedMs ?: JSONObject.NULL)
                        .put("probeError", probe?.error ?: JSONObject.NULL)
                        .put("bulkBytes", bulk?.bytesRead ?: JSONObject.NULL)
                        .put("bulkMs", bulk?.elapsedMs ?: JSONObject.NULL)
                        .put("bulkStalledAt", bulk?.stalledAtBytes ?: JSONObject.NULL),
                )
                val probeText = when {
                    !connected -> "not connected ($stateText)"
                    probe?.httpStatus != null -> "probe OK ${probe.elapsedMs}ms"
                    else -> "probe FAIL ${probe?.error}"
                }
                val bulkText = bulk?.let { b -> ", 256KB ${b.bytesRead}B/${b.elapsedMs}ms${b.stalledAtBytes?.let { " STALL@$it" } ?: ""}" } ?: ""
                onLine("  +${(now - start) / 1000}s $probeText$bulkText")
                sampleIndex++
            }
            delay(MONITOR_TICK_MS)
        }
        val elapsed = (clock() - start).coerceAtLeast(1)
        return JSONObject()
            .put("durationMs", elapsed)
            .put("connectedPercent", connectedMs * 100 / elapsed)
            .put("probeSuccess", "$probesOk/$probesTotal")
            .put("reconnects", reconnects)
            .put("events", events)
            .put("samples", samples)
    }

    private suspend fun directProbes(manifest: EndpointManifest?, onLine: (String) -> Unit): FieldDirectProbes {
        val dns = FieldTestTargets.DIRECT_DNS.map { probes.dns(it, null) }
        dns.forEach { onLine("  DNS ${it.host}: ${if (it.ok) it.addresses.joinToString(",") else "FAIL ${it.error}"}") }

        val http = mutableListOf<HttpProbeResult>()
        FieldTestTargets.DIRECT_HTTP.forEach { (label, url) -> http += probes.https(label, url, null, 64 * 1024, false) }
        // The device's own public IP is deliberately dropped; loc/colo say which country/edge saw us.
        http += probes.https("Cloudflare trace", FieldTestTargets.CLOUDFLARE_TRACE, null, 4 * 1024, true)
            .let { it.copy(trace = it.trace - "ip") }
        http += probes.https("Cloudflare 256KB (throttling check)", FieldTestTargets.BULK_DIRECT, null, 262_144, false)

        val tcp = mutableListOf<TcpProbeResult>()
        val ipHosts = linkedSetOf<String>()
        manifest?.endpoints?.forEach { e ->
            e.transports.forEach { b ->
                if (IPV4_LITERAL.matches(b.host)) ipHosts += b.host
                if (b.kind !in UDP_KINDS) tcp += probes.tcp("${e.id.value} ${b.kind} tcp/${b.port}", b.host, b.port, null)
                if (!IPV4_LITERAL.matches(b.host)) {
                    http += probes.https("${e.id.value} ${b.kind} CDN edge https://${b.host}/", "https://${b.host}/", null, 16 * 1024, false)
                }
            }
        }
        ipHosts.forEach { ip ->
            http += probes.https("Gateway $ip control plane 443", "https://$ip/v1/tunnel-probe", null, 1024, false)
            tcp += probes.tcp("Gateway $ip tcp/443", ip, 443, null)
        }
        http += probes.https(
            "Control plane ${FieldTestTargets.CONTROL_PLANE_HOST}",
            "https://${FieldTestTargets.CONTROL_PLANE_HOST}/v1/tunnel-probe", null, 1024, false,
        )
        if (manifest == null) onLine("  WARNING: no trusted manifest - gateway port probes skipped")
        http.forEach { onLine("  ${it.label}: ${if (it.ok) "OK ${it.httpStatus}" else "FAIL ${it.error ?: it.httpStatus}"}") }
        tcp.forEach { onLine("  ${it.label}: ${if (it.ok) "OK ${it.elapsedMs}ms" else "FAIL ${it.error}"}") }
        return FieldDirectProbes(dns, http, tcp)
    }

    private suspend fun runOne(target: FieldAttemptTarget, manifest: EndpointManifest?, directResolver: List<String>): FieldTransportRun {
        val startedAt = clock()
        // A relay run exits at the ingress' relayTo endpoint; Auto may exit anywhere.
        val endpointId = target.gateway?.let { host.endpointIdFor(it) }
            ?: target.relayIngress?.let { id -> manifest?.endpoints?.firstOrNull { it.id.value == id }?.relayTo?.value }
        if (target.gateway != null && target.gateway !in host.provisionedGateways()) {
            return FieldTransportRun(target, startedAt, FieldRunOutcome.SKIPPED, skipReason = "gateway not activated on this device")
        }
        if (target.gateway != null && target.transport != null && manifest != null) {
            val descriptor = manifest.endpoints.firstOrNull { it.id.value == endpointId }
            if (descriptor == null || !descriptor.supports(target.transport)) {
                return FieldTransportRun(target, startedAt, FieldRunOutcome.SKIPPED, skipReason = "not offered by the signed manifest for this gateway")
            }
        }
        host.applyTarget(target)?.let { reason ->
            return FieldTransportRun(target, startedAt, FieldRunOutcome.SKIPPED, skipReason = reason)
        }
        val scores = host.transportScores().mapKeys { it.key.name }
        val expected = expectedExitIps(manifest, endpointId)
        val errorBefore = host.lastErrorText()
        // A failed previous run can leave the controller in Error/HandshakeFailed
        // (disconnect() of an idle transport does not reset it). That state is
        // not this attempt's result: it only counts once the attempt is seen in
        // progress, or once it has changed.
        val leftover = host.transportState.value.takeIf { it is TransportState.Error || it is TransportState.HandshakeFailed }
        var sawProgress = false
        val connectStart = clock()
        var terminal: TransportState? = null
        var leftoverOnly = false
        coroutineScope {
            val watcher = launch(start = CoroutineStart.UNDISPATCHED) {
                host.transportState.collect { s ->
                    if (s is TransportState.Connecting || s is TransportState.Reconnecting || s is TransportState.Disconnecting) sawProgress = true
                }
            }
            host.connect()

            // Wait for Connected or a terminal failure. Polled, not collected: an
            // attempt the app refuses up front may never leave Disconnected, and a
            // StateFlow does not re-emit an unchanged value.
            var sawActivity = false
            while (clock() - connectStart < timings.connectTimeoutMs) {
                val s = host.transportState.value
                val stale = leftover != null && s == leftover && !sawProgress
                if (s !is TransportState.Disconnected && !stale) sawActivity = true
                val done = when {
                    stale -> clock() - connectStart > timings.notStartedGraceMs
                    s is TransportState.Connected || s is TransportState.Error || s is TransportState.HandshakeFailed -> true
                    s is TransportState.Disconnected -> sawActivity || clock() - connectStart > timings.notStartedGraceMs
                    else -> false
                }
                if (done) {
                    terminal = s
                    leftoverOnly = stale
                    break
                }
                delay(POLL_MS)
            }
            watcher.cancel()
        }
        val timedOut = terminal == null
        val connected = terminal is TransportState.Connected
        val connectMs = if (connected) clock() - connectStart else null
        val state = host.transportState.value
        val errorText = when {
            leftoverOnly -> host.lastErrorText()?.takeIf { it != errorBefore }
                ?: "attempt not observed - the previous run's ${leftover?.label()} never changed"
            terminal is TransportState.Error -> (terminal as TransportState.Error).message
            else -> host.lastErrorText()?.takeIf { it != errorBefore || !connected }
        }

        var health: VpnSessionHealth = host.sessionHealth.value
        var dns: DnsProbeResult? = null
        val probeResults = mutableListOf<HttpProbeResult>()
        var throughput: HttpProbeResult? = null
        val stability = mutableListOf<HttpProbeResult>()
        var exitIp: String? = null
        var exitColo: String? = null
        var exitLoc: String? = null
        val notes = mutableListOf<String>()
        var leaks: JSONObject? = null
        var core: List<net.pocvpn.client.vpn.xray.XrayProcessBridge.CoreMeasurement>? = null
        var appExcluded = false
        val coreMeasured = connected && host.currentTransportKind.value in XRAY_FAMILY
        if (coreMeasured) {
            health = withTimeoutOrNull(timings.healthGraceMs) {
                host.sessionHealth.first { it is VpnSessionHealth.DirectProtected || it is VpnSessionHealth.RelayProtected || it is VpnSessionHealth.Failed }
            } ?: host.sessionHealth.value
            delay(timings.settleMs)
            val urls = listOf(FieldTestTargets.CONNECTIVITY_204) +
                expected.sorted().take(1).map { "https://$it/v1/tunnel-probe" } +
                listOf("https://telegram.org/", "https://www.youtube.com/")
            core = host.measureViaXrayCore(urls)
            notes += "app is excluded from the Xray tunnel by design; data plane measured by the Xray core (latency only - no bulk download, exit IP or leak check)"
            if (core == null) notes += "the Xray process did not answer the measurement request"
            delay(timings.stabilityHoldMs)
            host.measureViaXrayCore(listOf(FieldTestTargets.CONNECTIVITY_204))?.let { later -> core = core.orEmpty() + later.map { it.copy(url = it.url + " (after hold)") } }
        } else if (connected) {
            health = withTimeoutOrNull(timings.healthGraceMs) {
                host.sessionHealth.first { it is VpnSessionHealth.DirectProtected || it is VpnSessionHealth.RelayProtected || it is VpnSessionHealth.Failed }
            } ?: host.sessionHealth.value
            delay(timings.settleMs)
            val vpn = host.vpnNetwork()
            if (vpn == null) notes += "no VPN network visible to the app - in-tunnel probes ran unbound"
            dns = probes.dns(FieldTestTargets.TUNNEL_DNS, vpn)
            val first = probes.https(FieldTestTargets.TUNNEL_HTTP.first().first, FieldTestTargets.TUNNEL_HTTP.first().second, vpn, 64 * 1024, false)
            probeResults += first
            if (first.error?.contains("EPERM") == true) {
                appExcluded = true
                notes += "this VPN excludes the Nova app (binding to the VPN network: EPERM); connection confirmed by the transport, data plane not measurable from the app - verify with a browser"
            }
        }
        if (connected && !coreMeasured && !appExcluded) {
            val vpn = host.vpnNetwork()
            FieldTestTargets.TUNNEL_HTTP.drop(1).forEach { (label, url) -> probeResults += probes.https(label, url, vpn, 64 * 1024, false) }
            val trace = probes.https("Cloudflare trace (exit)", FieldTestTargets.CLOUDFLARE_TRACE, vpn, 4 * 1024, true)
            probeResults += trace
            exitIp = trace.trace["ip"]
            exitColo = trace.trace["colo"]
            exitLoc = trace.trace["loc"]
            throughput = probes.https("Bulk 1MB", FieldTestTargets.BULK_TUNNEL, vpn, 1_048_576, false)
            delay(timings.stabilityHoldMs)
            stability += probes.https("Google 204 after hold", FieldTestTargets.CONNECTIVITY_204, vpn, 4 * 1024, false)
            stability += probes.https("Cloudflare trace after hold", FieldTestTargets.CLOUDFLARE_TRACE, vpn, 4 * 1024, true)
            leaks = probes.leaks(vpn, directResolver)
            if (host.transportState.value !is TransportState.Connected) notes += "session left Connected during probes: ${host.transportState.value.label()}"
        }
        if (target.relayIngress != null) {
            notes += "relay ingress ${target.relayIngress} on this device: ${host.relayIngressActivation(target.relayIngress)}"
            notes += "forced relay attempts kept: ${host.lastForcedRelayKeys()?.let { if (it.isEmpty()) "none (no relay candidate - ingress not activated or not eligible)" else it.joinToString(", ") } ?: "-"}"
        }
        val activeTransport = host.currentTransportKind.value?.name
        val session = host.latestDiagnosticSession()

        val disconnectStart = clock()
        val disconnectMs = if (host.transportState.value !is TransportState.Disconnected) {
            disconnectAndWait()
            clock() - disconnectStart
        } else {
            null
        }
        return FieldTransportRun(
            target = target,
            startedAtEpochMillis = startedAt,
            outcome = core?.let { measured -> if (measured.any { it.ok }) FieldRunOutcome.DATA_PLANE_CORE_CONFIRMED else FieldRunOutcome.CONNECTED_NO_DATA }
                ?: if (coreMeasured) FieldRunOutcome.CONNECTED_NO_DATA
                else if (appExcluded) FieldRunOutcome.CONNECTED_APP_EXCLUDED
                else classifyRun(connected, if (leftoverOnly) NOT_STARTED else state.label(), errorText, timedOut, probeResults, throughput, stability, exitIp, expected),
            connectMs = connectMs,
            terminalState = if (leftoverOnly) NOT_STARTED else (terminal ?: state).label(),
            errorMessage = errorText,
            activeTransport = activeTransport,
            sessionHealth = health.label(),
            expectedExitIps = expected,
            exitIp = exitIp,
            exitColo = exitColo,
            exitLoc = exitLoc,
            dns = dns,
            probes = probeResults,
            throughput = throughput,
            stability = stability,
            transportScoresBefore = scores,
            diagnosticSession = session,
            disconnectMs = disconnectMs,
            notes = notes,
            leaks = leaks,
            coreMeasurements = core,
        )
    }

    private suspend fun disconnectAndWait() {
        host.disconnect()
        withTimeoutOrNull(timings.disconnectTimeoutMs) {
            host.transportState.first { it is TransportState.Disconnected || it is TransportState.Error || it is TransportState.HandshakeFailed }
        }
    }
}
