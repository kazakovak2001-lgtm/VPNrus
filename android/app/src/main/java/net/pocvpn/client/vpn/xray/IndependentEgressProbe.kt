package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CompletableDeferred
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.IndependentEgressProbeResult
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog

/**
 * B-WL7 M1 - the pure parts of the independent-egress probe (no Android):
 * target choice, reply correlation and the decisions on both sides of the
 * `ACTION_PROBE_INDEPENDENT_EGRESS` exchange.
 *
 * Why another gateway: a probe to the CURRENT gateway's own
 * `/v1/tunnel-probe` leaves its Xray `freedom` outbound towards its own
 * public address and is answered by its own nginx (gateway/DEPLOYMENT.md),
 * so it never touches the egress a dead exit loses. The other catalog
 * gateway (different provider and region, same static nginx 200, an IP
 * certificate for its own address) can only be reached through the
 * current gateway's real egress.
 */
object IndependentEgressTargets {

    /**
     * The probe hosts for a session on [currentEndpointId]: every OTHER
     * catalog gateway's public address. Empty when the current endpoint is
     * not a catalog gateway - independence from it cannot be shown, so no
     * target is guessed.
     */
    fun forSession(currentEndpointId: EndpointId?): List<String> {
        if (currentEndpointId == null || ProductionGatewayCatalog.byEndpointId(currentEndpointId) == null) return emptyList()
        return ProductionGatewayCatalog.all
            .filter { it.endpointId != currentEndpointId }
            .map { it.awg.endpointHost }
            .filter { isIpv4Literal(it) }
    }

    /**
     * `:xray` side: the first candidate that is an IPv4 literal (no DNS, so
     * the IP certificate check binds the answer to that exact address) and
     * is neither the session's own server nor its relay exit. Null = no
     * independent target, never a fallback to the current gateway.
     */
    fun select(candidates: List<String>, sessionServerHost: String, relayExitHost: String?): String? =
        candidates.firstOrNull { it != sessionServerHost && it != relayExitHost && isIpv4Literal(it) }

    private val IPV4 = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")

    fun isIpv4Literal(host: String): Boolean =
        IPV4.matchEntire(host)?.groupValues?.drop(1)?.all { it.toInt() in 0..255 } == true
}

/**
 * Main-process side: completes once, with the first reply carrying THIS
 * request's id. Replies for other requests (late, from an earlier probe)
 * and duplicates are ignored; an unknown result name counts as NOT_REACHED.
 */
internal class EgressProbeReply(private val requestId: Long) {
    val result = CompletableDeferred<IndependentEgressProbeResult>()

    /** True only for the reply that completed [result]. */
    fun offer(replyRequestId: Long, resultName: String?): Boolean {
        if (replyRequestId != requestId) return false
        val parsed = IndependentEgressProbeResult.entries.firstOrNull { it.name == resultName } ?: IndependentEgressProbeResult.NOT_REACHED
        return result.complete(parsed)
    }
}

internal object IndependentEgressDecision {

    /**
     * Main process: REACHED only for a REACHED answer while the same
     * session is still the Started one; no answer or a changed session is
     * NOT_REACHED.
     */
    fun forCaller(answer: IndependentEgressProbeResult?, stillStartedSameSession: Boolean): IndependentEgressProbeResult = when {
        answer == null || !stillStartedSameSession -> IndependentEgressProbeResult.NOT_REACHED
        else -> answer
    }

    /**
     * `:xray` side: probes only for the session it was asked about, with
     * the core running, and re-checks the session afterwards so a restart
     * or a newer session during the probe can never be confirmed.
     */
    suspend fun forService(
        requestedSessionId: Long,
        currentSessionId: () -> Long,
        coreRunning: () -> Boolean,
        probe: suspend () -> IndependentEgressProbeResult,
    ): IndependentEgressProbeResult {
        if (requestedSessionId != currentSessionId() || !coreRunning()) return IndependentEgressProbeResult.NOT_REACHED
        val result = probe()
        return if (requestedSessionId == currentSessionId()) result else IndependentEgressProbeResult.NOT_REACHED
    }
}
