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
    /** True/false only when THIS endpoint's DATA-PLANE was probed specifically (e.g. a real connection attempt/handshake outcome for this exact endpoint+transport) - null when no such evidence exists. This is the RAW, as-observed value (for truthful diagnostics) - see [endpointSpecificReachableAgeMillis] for its own freshness, and ReachabilityEngine.assess's own docs for why [EndpointReachability.state] does NOT trust this value once it's stale, independent of what this field still shows. */
    val endpointSpecificReachable: Boolean?,
    val networkUsable: Boolean,
    val restrictionClass: RestrictionClass,
    /**
     * B12 - a SEPARATE signal from [endpointSpecificReachable]: whether the
     * CONTROL PLANE (the HTTPS API this endpoint's operator runs - manifest
     * distribution, activation, provisioning) answered, independent of
     * whether the DATA PLANE (the actual tunnel this endpoint's transports
     * carry) is reachable. For today's single production endpoint these
     * happen to be the same physical server, but the task's "do not
     * collapse control-plane-reachable/endpoint-reachable/transport-healthy"
     * requirement means this must be modeled as its own field even before a
     * deployment exists where they genuinely differ (e.g. a control plane
     * fronting several data-plane-only gateways). Defaults to null (never
     * probed) so every pre-B12 call site is unaffected - appended last,
     * never inserted mid-constructor, so existing POSITIONAL call sites
     * (this codebase's convention throughout its test suites) stay correct.
     */
    val controlPlaneReachable: Boolean? = null,
    /**
     * B12 (PR #24 audit fix) - how old [endpointSpecificReachable] is, in
     * the SAME real-clock units as [transportHealthAgeMillis] but tracked
     * SEPARATELY - the age of the specific per-endpoint outcome that
     * produced [endpointSpecificReachable], never [transportHealthAgeMillis]
     * reused as a stand-in (a transport can stay "recently probed" in
     * aggregate while this exact endpoint hasn't been attempted in a long
     * time - collapsing the two ages would silently revive stale
     * endpoint-specific evidence forever, exactly the bug this field fixes).
     * Null whenever [endpointSpecificReachable] is null, OR when a caller
     * supplied a reachable/unreachable value without a timestamp (treated
     * identically to "unknown freshness", which ReachabilityEngine.assess
     * never trusts as current - see its own docs). Appended last, after
     * [controlPlaneReachable], so existing positional call sites stay correct.
     */
    val endpointSpecificReachableAgeMillis: Long? = null,
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
 *  3. Stale TRANSPORT-WIDE evidence (older than [staleAfterMillis]), with no
 *     FRESH endpoint-specific evidence either -> UNKNOWN, regardless of what
 *     it once said - a resolved failure must not linger forever, and a
 *     stale success must not be trusted indefinitely either.
 *  4. FRESH endpoint-specific evidence (a real probe/attempt against THIS
 *     endpoint, no older than [endpointEvidenceStaleAfterMillis] - see
 *     [endpointSpecificOutcomeEpochMillis]'s own docs for exactly what
 *     "fresh" requires) is the strongest signal available and is checked
 *     before the transport-wide aggregate:
 *       - reachable == true -> REACHABLE
 *       - reachable == false AND transport health is HEALTHY elsewhere ->
 *         DEGRADED (conflicting evidence: the transport itself is proven to
 *         work somewhere, but not observably at this endpoint - a
 *         conservative middle state, never a full UNREACHABLE from that
 *         alone)
 *       - reachable == false otherwise -> UNREACHABLE
 *  5. STALE endpoint-specific evidence (or none at all): fall back to the
 *     transport-wide TransportHealthState mapping (HEALTHY->REACHABLE,
 *     DEGRADED->DEGRADED, UNREACHABLE/NOT_IMPLEMENTED->UNREACHABLE,
 *     UNKNOWN->UNKNOWN) - a stale endpoint-specific outcome NEVER continues
 *     to override current reachability once it has expired (PR #24 audit
 *     fix - see [endpointSpecificOutcomeEpochMillis]'s own docs for the bug
 *     this closes).
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
        // B12 - carried through truthfully into [ReachabilityEvidenceSummary]
        // for diagnostics ONLY - deliberately does NOT change [state] below
        // (same "real evidence, truthfully surfaced, not yet decision-driving"
        // boundary already established for RestrictionClassifier/TransportHealth
        // elsewhere in this codebase). A future slice may fold it into the
        // state derivation once there's a real deployment where control-plane
        // and data-plane reachability genuinely diverge to design that rule
        // against - see class docs' own "do not collapse" note.
        controlPlaneReachable: Boolean? = null,
        /**
         * B12 (PR #24 audit fix) - the REAL timestamp of the specific
         * (endpoint, transport) outcome [endpointSpecificReachable] reports
         * on - e.g. `ConnectionOutcome.timestampEpochMillis` for whichever
         * outcome the caller matched. REQUIRED (no default) whenever
         * [endpointSpecificReachable] is non-null: a caller supplying a
         * true/false value with no timestamp gets that evidence treated as
         * immediately stale (see below) - this deliberately forces every
         * call site to either supply real freshness or accept the
         * conservative fallback, rather than silently trusting an
         * undated value forever. NEVER [transportHealth.lastProbeEpochMillis]
         * reused as a stand-in - that measures a DIFFERENT thing (see class
         * docs' own "not TransportHealth's age" note).
         */
        endpointSpecificOutcomeEpochMillis: Long? = null,
        /** Independent TTL from [staleAfterMillis] - endpoint-specific evidence and transport-wide evidence can legitimately need different freshness windows. Defaults to the same value for now. */
        endpointEvidenceStaleAfterMillis: Long = DEFAULT_STALE_AFTER_MILLIS,
    ): EndpointReachability {
        val ageMillis = transportHealth.lastProbeEpochMillis?.let { nowEpochMillis - it }

        // Age is null (never "0", never borrowed from transportHealth) when
        // there is no timestamp - that null is exactly what makes the
        // freshness check below fail closed for an undated value.
        val endpointEvidenceAgeMillis = endpointSpecificReachable?.let {
            endpointSpecificOutcomeEpochMillis?.let { ts -> nowEpochMillis - ts }
        }
        // PR #24 second audit fix - a negative age (the outcome's own
        // timestamp is AFTER `nowEpochMillis`, from a backwards clock jump
        // or a future-dated value) must NOT count as "fresh" just because
        // it's numerically <= the TTL. Freshness requires the evidence to
        // be from the past, full stop - `>= 0` is the explicit lower bound.
        val endpointEvidenceIsFresh = endpointEvidenceAgeMillis != null &&
            endpointEvidenceAgeMillis in 0..endpointEvidenceStaleAfterMillis
        // The value STATE derivation is allowed to act on - null whenever
        // the raw evidence is missing OR has expired, even though the raw
        // observed value is still reported truthfully in [evidence] below.
        val freshEndpointSpecificReachable = if (endpointEvidenceIsFresh) endpointSpecificReachable else null

        val evidence = ReachabilityEvidenceSummary(
            transportHealthState = transportHealth.state,
            transportHealthAgeMillis = ageMillis,
            endpointSpecificReachable = endpointSpecificReachable,
            networkUsable = networkUsable,
            restrictionClass = restrictionClass,
            controlPlaneReachable = controlPlaneReachable,
            endpointSpecificReachableAgeMillis = endpointEvidenceAgeMillis,
        )

        val state = when {
            !endpoint.supports(transportKind) -> ReachabilityState.UNREACHABLE
            !networkUsable -> ReachabilityState.UNKNOWN
            ageMillis != null && ageMillis > staleAfterMillis && freshEndpointSpecificReachable == null -> ReachabilityState.UNKNOWN
            freshEndpointSpecificReachable == true -> ReachabilityState.REACHABLE
            freshEndpointSpecificReachable == false && transportHealth.state == TransportHealthState.HEALTHY -> ReachabilityState.DEGRADED
            freshEndpointSpecificReachable == false -> ReachabilityState.UNREACHABLE
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
