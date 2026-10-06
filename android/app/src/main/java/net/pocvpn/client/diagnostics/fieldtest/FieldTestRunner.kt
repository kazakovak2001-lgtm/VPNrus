package net.pocvpn.client.diagnostics.fieldtest

import android.net.Network
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeoutOrNull
import net.pocvpn.client.reachability.EndpointManifest
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
    fun latestDiagnosticSession(): JSONObject?
    fun appState(): JSONObject
    fun supportBundle(): JSONObject?
    fun networkContext(): JSONObject
    fun vpnNetwork(): Network?
    fun appInfo(): JSONObject
    fun deviceInfo(): JSONObject
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

/** Pure: the attempt list for a run. Every gateway x transport, then Smart Connect. */
internal fun planAttempts(gateways: List<ProductionGatewayId>): List<FieldAttemptTarget> =
    gateways.flatMap { g -> FIELD_TEST_TRANSPORTS.map { FieldAttemptTarget(g, it) } } +
        FieldAttemptTarget(null, null)

/** Pure: IP-literal hosts of [endpointId]'s signed bindings (all endpoints when null). */
internal fun expectedExitIps(manifest: EndpointManifest?, endpointId: String?): Set<String> {
    val endpoints = manifest?.endpoints.orEmpty().filter { endpointId == null || it.id.value == endpointId }
    return endpoints.flatMap { e -> e.transports.map { it.host } }.filter { IPV4_LITERAL.matches(it) }.toSet()
}

private val IPV4_LITERAL = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
private const val POLL_MS = 250L

class FieldTestRunner(
    private val host: FieldTestHost,
    private val probes: FieldProbeSet = FieldProbeSet(),
    private val timings: FieldTestTimings = FieldTestTimings(),
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val log = mutableListOf<String>()

    suspend fun run(onProgress: (FieldTestProgress) -> Unit): FieldTestReport {
        val startedAt = clock()
        val gateways = ProductionGatewayId.entries.toList()
        val attempts = planAttempts(gateways)
        val totalSteps = attempts.size + 2
        var step = 0
        fun progress(phase: String, line: String? = null) {
            line?.let { log += it }
            onProgress(FieldTestProgress(true, phase, step, totalSteps, log.toList()))
        }

        val manifest = host.trustedManifest()
        val networkBefore = host.networkContext()
        val appBefore = host.appState()
        val saved = host.saveSelection()
        val runs = mutableListOf<FieldTransportRun>()
        var direct: FieldDirectProbes? = null
        var abort: String? = null
        var cancelled = false
        try {
            progress("Preparing", "Network: ${networkBefore.optString("summary")}")
            if (!host.vpnPermissionGranted()) {
                abort = "VPN permission not granted - connect once from the home screen first"
            } else {
                if (host.transportState.value !is TransportState.Disconnected) {
                    progress("Preparing", "Disconnecting the current session first")
                    disconnectAndWait()
                }
                step++
                progress("Direct probes", "Direct (outside VPN) probes...")
                direct = directProbes(manifest) { progress("Direct probes", it) }
                attempts.forEach { target ->
                    step++
                    progress("VPN runs", "[$step/$totalSteps] ${target.label}")
                    val run = runOne(target, manifest)
                    runs += run
                    progress("VPN runs", "  -> ${run.outcome}${run.exitIp?.let { " exit $it" } ?: ""}${run.errorMessage?.let { " ($it)" } ?: run.skipReason?.let { " ($it)" } ?: ""}")
                    if (run.outcome != FieldRunOutcome.SKIPPED) delay(timings.betweenRunsMs)
                }
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // Cancel still yields a (partial) report - every finished run is evidence.
            cancelled = true
            log += "Cancelled by the user."
        } finally {
            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) {
                if (host.transportState.value !is TransportState.Disconnected) disconnectAndWait()
                host.restoreSelection(saved)
            }
        }
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
        )
        abort?.let { log += "ABORTED: $it" }
        log += "Done."
        onProgress(FieldTestProgress(false, "Done", totalSteps, totalSteps, log.toList(), report))
        return report
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

    private suspend fun runOne(target: FieldAttemptTarget, manifest: EndpointManifest?): FieldTransportRun {
        val startedAt = clock()
        val endpointId = target.gateway?.let { host.endpointIdFor(it) }
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
        val connectStart = clock()
        host.connect()

        // Wait for Connected or a terminal failure. Polled, not collected: an
        // attempt the app refuses up front may never leave Disconnected, and a
        // StateFlow does not re-emit an unchanged value.
        var sawActivity = false
        var terminal: TransportState? = null
        while (clock() - connectStart < timings.connectTimeoutMs) {
            val s = host.transportState.value
            if (s !is TransportState.Disconnected) sawActivity = true
            val done = when (s) {
                is TransportState.Connected, is TransportState.Error, is TransportState.HandshakeFailed -> true
                is TransportState.Disconnected -> sawActivity || clock() - connectStart > timings.notStartedGraceMs
                else -> false
            }
            if (done) {
                terminal = s
                break
            }
            delay(POLL_MS)
        }
        val timedOut = terminal == null
        val connected = terminal is TransportState.Connected
        val connectMs = if (connected) clock() - connectStart else null
        val state = host.transportState.value
        val errorText = when (terminal) {
            is TransportState.Error -> terminal.message
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
        if (connected) {
            health = withTimeoutOrNull(timings.healthGraceMs) {
                host.sessionHealth.first { it is VpnSessionHealth.DirectProtected || it is VpnSessionHealth.RelayProtected || it is VpnSessionHealth.Failed }
            } ?: host.sessionHealth.value
            delay(timings.settleMs)
            val vpn = host.vpnNetwork()
            if (vpn == null) notes += "no VPN network visible to the app - in-tunnel probes ran unbound"
            dns = probes.dns(FieldTestTargets.TUNNEL_DNS, vpn)
            FieldTestTargets.TUNNEL_HTTP.forEach { (label, url) -> probeResults += probes.https(label, url, vpn, 64 * 1024, false) }
            val trace = probes.https("Cloudflare trace (exit)", FieldTestTargets.CLOUDFLARE_TRACE, vpn, 4 * 1024, true)
            probeResults += trace
            exitIp = trace.trace["ip"]
            exitColo = trace.trace["colo"]
            exitLoc = trace.trace["loc"]
            throughput = probes.https("Bulk 1MB", FieldTestTargets.BULK_TUNNEL, vpn, 1_048_576, false)
            delay(timings.stabilityHoldMs)
            stability += probes.https("Google 204 after hold", FieldTestTargets.CONNECTIVITY_204, vpn, 4 * 1024, false)
            stability += probes.https("Cloudflare trace after hold", FieldTestTargets.CLOUDFLARE_TRACE, vpn, 4 * 1024, true)
            if (host.transportState.value !is TransportState.Connected) notes += "session left Connected during probes: ${host.transportState.value}"
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
            outcome = classifyRun(connected, state.toString(), errorText, timedOut, probeResults, throughput, stability, exitIp, expected),
            connectMs = connectMs,
            terminalState = (terminal ?: state).toString(),
            errorMessage = errorText,
            activeTransport = activeTransport,
            sessionHealth = health.toString(),
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
        )
    }

    private suspend fun disconnectAndWait() {
        host.disconnect()
        withTimeoutOrNull(timings.disconnectTimeoutMs) {
            host.transportState.first { it is TransportState.Disconnected || it is TransportState.Error || it is TransportState.HandshakeFailed }
        }
    }
}
