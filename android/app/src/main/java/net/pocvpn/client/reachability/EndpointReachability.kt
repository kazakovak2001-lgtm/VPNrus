package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind

/**
 * Conservative reachability states. Never a stronger claim than the evidence
 * supports - see ReachabilityEngine's own docs for exactly which evidence
 * produces which state. Deliberately has no per-protocol
 * DPI/censorship-specific value, same discipline as RestrictionClass.
 */
enum class ReachabilityState {
    UNKNOWN,
    REACHABLE,
    DEGRADED,
    UNREACHABLE,
}

/**
 * B11 - answers "can THIS endpoint be reached through THIS transport on THIS
 * network", which is a strictly narrower question than [TransportHealth]
 * ("does this transport tend to work at all") - see ReachabilityEngine's own
 * docs for why these two models are kept separate rather than collapsed.
 * [evidence] carries through exactly what was used to reach [state], for
 * truthful diagnostics.
 */
data class EndpointReachability(
    val endpointId: EndpointId,
    val transportKind: TransportKind,
    val state: ReachabilityState,
    val latencyMillis: Long? = null,
    val lastSuccessEpochMillis: Long? = null,
    val lastFailureEpochMillis: Long? = null,
    val evidence: ReachabilityEvidenceSummary,
)

/**
 * What ReachabilityEngine.assess actually looked at - never anything beyond
 * this closed field set (same "closed evidence set" discipline as
 * RestrictionEvidence). No browsing destination, DNS history, SSID, IMSI, or
 * user traffic ever appears here - only already-existing, already-privacy-
 * reviewed signals this codebase collects for other reasons.
 */
data class ReachabilityEvidenceSummary(
    val transportHealthState: TransportHealthState,
    val transportHealthAgeMillis: Long?,
    /** True/false only when THIS endpoint specifically was probed (e.g. the pinned gateway's own HTTPS probe) - null when no endpoint-specific evidence exists. */
    val endpointSpecificReachable: Boolean?,
    val networkUsable: Boolean,
    val restrictionClass: RestrictionClass,
)

/**
 * B11 - deterministic, pure. Consumes REAL evidence this codebase already
 * collects (TransportHealthCalculator's output, GatewayReachabilityProbe's
 * result, NetworkProfiler's usability, RestrictionClassifier's output) and
 * produces one typed assessment. Introduces NO new probing of its own - see
 * task scope "do not introduce aggressive probing".
 *
 * Priority (first match wins), most conservative rule first:
 *  1. Transport not supported at this endpoint at all -> UNREACHABLE (no
 *     amount of general transport health matters if this endpoint can't
 *     even speak this transport).
 *  2. No usable network -> UNKNOWN (absence of network says nothing about
 *     the endpoint itself - never claim UNREACHABLE from a state that isn't
 *     about the endpoint).
 *  3. Stale evidence (older than [staleAfterMillis]) -> UNKNOWN, regardless
 *     of what it once said - a resolved failure must not linger forever,
 *     and a stale success must not be trusted indefinitely either.
 *  4. Endpoint-specific evidence (a real probe against THIS endpoint) is the
 *     strongest signal available and is checked before the transport-wide
 *     aggregate:
 *       - reachable == true -> REACHABLE
 *       - reachable == false AND transport health is HEALTHY elsewhere ->
 *         DEGRADED (conflicting evidence: the transport itself is proven to
 *         work somewhere, but not observably at this endpoint - a
 *         conservative middle state, never a full UNREACHABLE from that
 *         alone)
 *       - reachable == false otherwise -> UNREACHABLE
 *  5. No endpoint-specific evidence: fall back to the transport-wide
 *     TransportHealthState mapping (HEALTHY->REACHABLE, DEGRADED->DEGRADED,
 *     UNREACHABLE/NOT_IMPLEMENTED->UNREACHABLE, UNKNOWN->UNKNOWN).
 */
object ReachabilityEngine {

    /** Evidence older than this is treated as UNKNOWN rather than trusted - see class docs rule 3. */
    const val DEFAULT_STALE_AFTER_MILLIS: Long = 30 * 60 * 1000L

    fun assess(
        endpoint: EndpointDescriptor,
        transportKind: TransportKind,
        networkUsable: Boolean,
        transportHealth: TransportHealth,
        endpointSpecificReachable: Boolean?,
        restrictionClass: RestrictionClass,
        nowEpochMillis: Long,
        staleAfterMillis: Long = DEFAULT_STALE_AFTER_MILLIS,
    ): EndpointReachability {
        val ageMillis = transportHealth.lastProbeEpochMillis?.let { nowEpochMillis - it }
        val evidence = ReachabilityEvidenceSummary(
            transportHealthState = transportHealth.state,
            transportHealthAgeMillis = ageMillis,
            endpointSpecificReachable = endpointSpecificReachable,
            networkUsable = networkUsable,
            restrictionClass = restrictionClass,
        )

        val state = when {
            !endpoint.supports(transportKind) -> ReachabilityState.UNREACHABLE
            !networkUsable -> ReachabilityState.UNKNOWN
            ageMillis != null && ageMillis > staleAfterMillis && endpointSpecificReachable == null -> ReachabilityState.UNKNOWN
            endpointSpecificReachable == true -> ReachabilityState.REACHABLE
            endpointSpecificReachable == false && transportHealth.state == TransportHealthState.HEALTHY -> ReachabilityState.DEGRADED
            endpointSpecificReachable == false -> ReachabilityState.UNREACHABLE
            else -> mapTransportHealth(transportHealth.state)
        }

        return EndpointReachability(
            endpointId = endpoint.id,
            transportKind = transportKind,
            state = state,
            latencyMillis = transportHealth.latencyMillis,
            lastSuccessEpochMillis = if (transportHealth.state == TransportHealthState.HEALTHY) transportHealth.lastProbeEpochMillis else null,
            lastFailureEpochMillis = if (transportHealth.consecutiveFailures > 0) transportHealth.lastProbeEpochMillis else null,
            evidence = evidence,
        )
    }

    private fun mapTransportHealth(state: TransportHealthState): ReachabilityState = when (state) {
        TransportHealthState.HEALTHY -> ReachabilityState.REACHABLE
        TransportHealthState.DEGRADED -> ReachabilityState.DEGRADED
        TransportHealthState.UNREACHABLE, TransportHealthState.NOT_IMPLEMENTED -> ReachabilityState.UNREACHABLE
        TransportHealthState.UNKNOWN -> ReachabilityState.UNKNOWN
    }
}
