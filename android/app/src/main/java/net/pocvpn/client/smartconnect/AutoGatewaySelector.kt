package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.PathCandidateBuilder
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.PathScorer
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B16 - one ranked, real candidate to ATTEMPT a connection through when the
 * user is in automatic gateway-selection mode. Carries every fact
 * PROJECT_ARCHITECTURE.md's "Candidate identity" invariant requires
 * ([gatewayId]/[endpointId]/[transport]/[configSnapshot]), all resolved
 * ONCE, at build time - MainViewModel must never re-derive gateway identity
 * after an attempt using this candidate has started.
 */
data class GatewayAttemptCandidate(
    val gatewayId: ProductionGatewayId,
    val endpointId: EndpointId,
    val transport: TransportKind,
    val region: String,
    val configSnapshot: GatewayConfigSnapshot,
    val score: Long,
    val reasons: List<String>,
)

/**
 * B16 - promotes the EXISTING, unmodified reachability/PathScorer pipeline
 * (ReachabilityEngine -> PathCandidateBuilder -> PathScorer - see
 * PROJECT_ARCHITECTURE.md's fixed pipeline order) into the real automatic
 * gateway-selection decision boundary. Deliberately NOT a second/parallel
 * scoring system: [PathScorer.score]/[PathScorer.rank] are called exactly
 * as `MainViewModel.reachabilityDiagnostics()` already calls them for its
 * own (observational) purpose - this object only adds the gateway-level
 * framing (candidate identity, bounded ordering, fail-closed/fallback
 * rules) around that existing, already-tested scorer.
 */
object AutoGatewaySelector {

    /** Never more than this many DISTINCT (gateway, transport) attempts per connect() request - bounded failover (task requirement 6). */
    const val MAX_ATTEMPTS = 4

    /**
     * Builds the full ranked candidate list across every PROVISIONED
     * production gateway - an unprovisioned gateway (no client tunnel
     * identity on this device) is silently excluded, the SAME readiness
     * check MainViewModel.provisionedGatewayIds already applies to the
     * manual picker: never a fabricated candidate for a gateway this device
     * cannot actually authenticate to. Empty when nothing is eligible -
     * callers must fail closed, never invent a fallback candidate (task
     * requirement 5's "no random gateway selection").
     *
     * [preference] mirrors the SAME UserTransportPreference a manually
     * selected gateway already honors: a user who has pinned
     * `Manual(kind)` gets exactly that transport kind across every gateway
     * candidate too - never silently overridden by automatic gateway mode.
     *
     * UNKNOWN reachability is never treated as UNREACHABLE (task
     * requirement 5) because this reuses [PathScorer.score] verbatim, whose
     * own reachability tier already ranks UNKNOWN strictly above DEGRADED
     * and UNREACHABLE (see PathScorer's own rank table) - never excluded
     * outright the way an ineligible (NOT AVAILABLE-registry) candidate is.
     */
    fun buildCandidates(
        gateways: List<ProductionGatewayDescriptor>,
        provisioned: (ProductionGatewayId) -> Boolean,
        clientTunnelIp: (ProductionGatewayId) -> String?,
        registryFor: (EndpointId) -> TransportRegistry,
        xrayAvailableFor: (EndpointId) -> Boolean,
        xrayTlsAvailableFor: (EndpointId) -> Boolean,
        reachabilityFor: (EndpointId, TransportKind) -> EndpointReachability,
        transportHealthFor: (TransportKind) -> TransportHealth,
        historyFor: (EndpointId, TransportKind) -> PathHistoryEntry?,
        preference: UserTransportPreference = UserTransportPreference.Auto,
    ): List<GatewayAttemptCandidate> {
        val eligibleGateways = gateways.filter { provisioned(it.id) && !clientTunnelIp(it.id).isNullOrBlank() }
        val pinnedKind = (preference as? UserTransportPreference.Manual)?.kind

        // Keyed by PathCandidate.Direct.id ("direct:<transport>:<endpointId>") -
        // already unique per (gateway, transport) pair, so this survives
        // PathScorer.rank()'s reordering without relying on object identity.
        val scoredByCandidateId = LinkedHashMap<String, Pair<ProductionGatewayDescriptor, PathScorer.PathScoreResult>>()

        eligibleGateways.forEach { gateway ->
            val endpoint = ProductionGatewayEndpoints.descriptorFor(
                gateway,
                xrayAvailable = xrayAvailableFor(gateway.endpointId),
                xrayTlsAvailable = xrayTlsAvailableFor(gateway.endpointId),
            )
            val registry = registryFor(gateway.endpointId)
            endpoint.transports.map { it.kind }
                .filter { pinnedKind == null || it == pinnedKind }
                .forEach { kind ->
                    val candidate = PathCandidateBuilder.buildDirect(endpoint, kind, reachabilityFor(gateway.endpointId, kind)) ?: return@forEach
                    val capabilities = registry.descriptorFor(kind)?.capabilities ?: TransportCapabilities.notImplemented()
                    val result = PathScorer.score(
                        candidate = candidate,
                        registry = registry,
                        capabilities = capabilities,
                        transportHealth = transportHealthFor(kind),
                        history = historyFor(gateway.endpointId, kind),
                        diverseProviderOrAsnSeenElsewhere = false,
                    )
                    if (result.eligible) scoredByCandidateId[candidate.id] = gateway to result
                }
        }

        val ranked = PathScorer.rank(scoredByCandidateId.values.map { it.second })
        return ranked.mapNotNull { result ->
            val (gateway, _) = scoredByCandidateId.getValue(result.candidate.id)
            val tunnelIp = clientTunnelIp(gateway.id) ?: return@mapNotNull null
            GatewayAttemptCandidate(
                gatewayId = gateway.id,
                endpointId = gateway.endpointId,
                transport = result.candidate.transport,
                region = "${gateway.displayCountry} / ${gateway.displayCity}",
                configSnapshot = snapshotFor(gateway, tunnelIp),
                score = result.score,
                reasons = result.reasons,
            )
        }
    }

    private fun snapshotFor(gateway: ProductionGatewayDescriptor, clientTunnelIp: String): GatewayConfigSnapshot = GatewayConfigSnapshot(
        endpointHost = gateway.awg.endpointHost,
        endpointPort = gateway.awg.endpointPort.toString(),
        serverPublicKey = gateway.awg.serverPublicKeyBase64,
        clientTunnelIp = clientTunnelIp,
        gatewayTunnelIp = gateway.awg.gatewayTunnelIp,
        allowedIps = "",
        profile = gateway.awgProfile,
    )

    /**
     * Advances [candidates] (already ranked, from [buildCandidates]) past
     * every (gateway, transport) pair in [attempted] and returns the next
     * one to try - null once every candidate has been attempted (task
     * requirement 6: "fail closed once the bounded candidate set is
     * exhausted") or [MAX_ATTEMPTS] distinct attempts have already happened
     * for this request. Never returns the same (gateway, transport) pair
     * twice for one [attempted] set, by construction - "never retry the
     * exact same gateway+transport indefinitely".
     */
    fun nextCandidate(
        candidates: List<GatewayAttemptCandidate>,
        attempted: Set<Pair<ProductionGatewayId, TransportKind>>,
    ): GatewayAttemptCandidate? {
        if (attempted.size >= MAX_ATTEMPTS) return null
        return candidates.firstOrNull { (it.gatewayId to it.transport) !in attempted }
    }
}
