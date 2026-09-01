package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointReachability
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.PathCandidate
import net.pocvpn.client.reachability.PathCandidateBuilder
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.PathScorer
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
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
 * B16/B17 - promotes the EXISTING, unmodified reachability/PathScorer
 * pipeline (ReachabilityEngine -> PathCandidateBuilder -> PathScorer - see
 * PROJECT_ARCHITECTURE.md's fixed pipeline order) into the real automatic
 * gateway-selection decision boundary. Deliberately NOT a second/parallel
 * scoring system: [PathScorer.score]/[PathScorer.rank] are called exactly
 * as `MainViewModel.reachabilityDiagnostics()` already calls them for its
 * own (observational) purpose - this object only adds the gateway-level
 * framing (candidate identity, bounded ordering, fail-closed/fallback
 * rules) around that existing, already-tested scorer.
 *
 * **B17 runtime-authority change**: gateway/path DISCOVERY - which endpoint
 * ids even exist as candidates - now comes from the caller's verified
 * `TrustedManifestState` (via [manifestEndpoints]), never directly from
 * `ProductionGatewayCatalog`. `ProductionGatewayCatalog` (via
 * [gatewayFactsFor]) is consulted only as a COMPATIBILITY lookup - for an
 * endpoint id the manifest has ALREADY named, it supplies the AWG
 * connection facts (server public key, gateway tunnel IP, obfuscation
 * profile) needed to actually dial it, none of which belong in the public
 * manifest (see EmbeddedBootstrapManifest's own docs on what must never be
 * embedded there). An endpoint present in the catalog but ABSENT from the
 * trusted manifest can never become a candidate this way - [gatewayFactsFor]
 * is only ever invoked with an [EndpointId] the manifest itself already
 * named, never iterated the other way around.
 */
object AutoGatewaySelector {

    /** Never more than this many DISTINCT (gateway, transport) attempts per connect() request - bounded failover (task requirement 6). */
    const val MAX_ATTEMPTS = 4

    /**
     * Builds the full ranked candidate list across every manifest-named
     * endpoint this device is ALSO locally PROVISIONED for - task
     * requirement 7's "combine verified public endpoint facts from the
     * trusted manifest WITH local per-device provisioned identity/profile
     * availability". [manifestEndpoints] should be
     * `(TrustedManifestState.Trusted.manifest.endpoints)` when something
     * verifies, or an empty list when nothing does (`NoneTrusted`) - an
     * empty list here always yields an empty candidate list, never a
     * fallback to the raw catalog (task requirement 9.D: fail closed, never
     * silently fall back to an unsigned catalog candidate).
     *
     * For each manifest endpoint, [gatewayFactsFor] resolves the LOCAL
     * connection facts needed to dial it (null if this device's catalog
     * has no such gateway at all - never a fabricated match); the endpoint
     * is then filtered by [provisioned]/[clientTunnelIp] - the SAME
     * readiness check MainViewModel.provisionedGatewayIds already applies
     * to the manual picker: never a fabricated candidate for a gateway this
     * device cannot actually authenticate to, and never a candidate merely
     * because the manifest names it (task requirement 7's own example -
     * "a manifest naming Stockholm does NOT imply this device is
     * provisioned for Stockholm"). Empty when nothing is eligible -
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
        manifestEndpoints: List<EndpointDescriptor>,
        gatewayFactsFor: (EndpointId) -> ProductionGatewayDescriptor?,
        provisioned: (ProductionGatewayId) -> Boolean,
        clientTunnelIp: (ProductionGatewayId) -> String?,
        registryFor: (EndpointId) -> TransportRegistry,
        xrayAvailableFor: (EndpointId) -> Boolean,
        xrayTlsAvailableFor: (EndpointId) -> Boolean,
        reachabilityFor: (EndpointId, TransportKind) -> EndpointReachability,
        transportHealthFor: (TransportKind) -> TransportHealth,
        historyFor: (EndpointId, TransportKind) -> PathHistoryEntry?,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        // B19 - threaded straight into PathScorer.score's own bounded,
        // time-decaying cooldown penalty (see that function's own docs).
        // Defaults to Long.MAX_VALUE - same "byte-for-byte unaffected unless
        // a caller opts in" contract PathScorer.score itself documents.
        nowEpochMillis: Long = Long.MAX_VALUE,
    ): List<GatewayAttemptCandidate> {
        val eligible = manifestEndpoints.mapNotNull { manifestEndpoint ->
            val gateway = gatewayFactsFor(manifestEndpoint.id) ?: return@mapNotNull null
            if (!provisioned(gateway.id) || clientTunnelIp(gateway.id).isNullOrBlank()) return@mapNotNull null
            gateway to manifestEndpoint
        }
        val pinnedKind = (preference as? UserTransportPreference.Manual)?.kind

        // B19 - a small, private, PRE-scoring pass: everything PathScorer.score
        // needs, gathered once per (gateway, transport) so the diversity bonus
        // below can be computed as a genuine per-candidate signal instead of
        // a single batch-wide Boolean (the exact bug this fixes - see
        // PathScorer's own docs and docs/ROADMAP.md's "Endpoint / Path
        // Reachability Fabric" row history for why the old call site was
        // disabled).
        data class Prepared(
            val gateway: ProductionGatewayDescriptor,
            val binding: EndpointTransportBinding,
            val candidate: PathCandidate,
            val registry: TransportRegistry,
            val capabilities: TransportCapabilities,
            val transportHealth: TransportHealth,
            val history: PathHistoryEntry?,
            val diversityKey: String,
        )

        val prepared = mutableListOf<Prepared>()
        eligible.forEach { (gateway, manifestEndpoint) ->
            // Local per-device profile availability gates WHICH of the
            // manifest's declared transport bindings this device can
            // actually use today (task requirement 7) - the manifest
            // merely says the endpoint SUPPORTS a transport kind at a
            // given host:port, never that this device has a usable
            // credential for it yet.
            val availableTransports = manifestEndpoint.transports.filter { binding ->
                when (binding.kind) {
                    TransportKind.AMNEZIA_WG -> true // already gated by provisioned()/clientTunnelIp() above
                    TransportKind.XRAY_REALITY -> xrayAvailableFor(manifestEndpoint.id)
                    TransportKind.TLS_TCP -> xrayTlsAvailableFor(manifestEndpoint.id)
                    else -> false
                }
            }
            if (availableTransports.isEmpty()) return@forEach
            val endpoint = manifestEndpoint.copy(transports = availableTransports)
            val registry = registryFor(gateway.endpointId)
            // B19 - the manifest's OWN provider/ASN (never the catalog's,
            // and never a fabricated preference) - prefers ASN when the
            // manifest names one (a strictly finer-grained signal than
            // provider name alone), falling back to provider.
            val diversityKey = endpoint.asn?.toString() ?: endpoint.provider
            endpoint.transports
                .filter { pinnedKind == null || it.kind == pinnedKind }
                .forEach { binding ->
                    val kind = binding.kind
                    val candidate = PathCandidateBuilder.buildDirect(endpoint, kind, reachabilityFor(gateway.endpointId, kind)) ?: return@forEach
                    val capabilities = registry.descriptorFor(kind)?.capabilities ?: TransportCapabilities.notImplemented()
                    prepared += Prepared(gateway, binding, candidate, registry, capabilities, transportHealthFor(kind), historyFor(gateway.endpointId, kind), diversityKey)
                }
        }

        // B19 - "troubled" providers/ASNs: ones this same batch already has
        // fresh negative evidence for (degraded/unreachable transport
        // health, a degraded/unreachable reachability read, or an active
        // this-network failure streak). A candidate whose OWN provider/ASN
        // is troubled never gets its own bonus (diversifying AWAY FROM
        // yourself makes no sense); a candidate on a clean provider/ASN gets
        // the bonus only when a genuinely troubled alternative exists
        // elsewhere in this batch - never an identical bonus handed to
        // every candidate regardless of the batch's actual composition.
        val troubledDiversityKeys = prepared.filter { p ->
            p.transportHealth.state == TransportHealthState.DEGRADED || p.transportHealth.state == TransportHealthState.UNREACHABLE ||
                p.candidate.hops.any { it.reachability.state == ReachabilityState.DEGRADED || it.reachability.state == ReachabilityState.UNREACHABLE } ||
                (p.history?.consecutiveFailures ?: 0) > 0
        }.map { it.diversityKey }.toSet()

        // Keyed by PathCandidate.Direct.id ("direct:<transport>:<endpointId>") -
        // already unique per (gateway, transport) pair, so this survives
        // PathScorer.rank()'s reordering without relying on object identity.
        // [binding] is the EXACT manifest transport binding this specific
        // candidate was built from - carried alongside the score so the
        // eventual GatewayConfigSnapshot's endpointHost/endpointPort are
        // resolved from THIS binding, never re-derived from the catalog
        // (see snapshotFor's own docs - the B17-2 runtime-authority fix).
        val scoredByCandidateId = LinkedHashMap<String, Triple<ProductionGatewayDescriptor, EndpointTransportBinding, PathScorer.PathScoreResult>>()
        prepared.forEach { p ->
            val diverse = troubledDiversityKeys.isNotEmpty() && p.diversityKey !in troubledDiversityKeys
            val result = PathScorer.score(
                candidate = p.candidate,
                registry = p.registry,
                capabilities = p.capabilities,
                transportHealth = p.transportHealth,
                history = p.history,
                diverseProviderOrAsnSeenElsewhere = diverse,
                nowEpochMillis = nowEpochMillis,
            )
            if (result.eligible) scoredByCandidateId[p.candidate.id] = Triple(p.gateway, p.binding, result)
        }

        val ranked = PathScorer.rank(scoredByCandidateId.values.map { it.third })
        return ranked.mapNotNull { result ->
            val (gateway, binding, _) = scoredByCandidateId.getValue(result.candidate.id)
            val tunnelIp = clientTunnelIp(gateway.id) ?: return@mapNotNull null
            GatewayAttemptCandidate(
                gatewayId = gateway.id,
                endpointId = gateway.endpointId,
                transport = result.candidate.transport,
                region = "${gateway.displayCountry} / ${gateway.displayCity}",
                configSnapshot = snapshotFor(gateway, binding, tunnelIp),
                score = result.score,
                reasons = result.reasons,
            )
        }
    }

    /**
     * B17-2 runtime-authority fix: [endpointHost]/[endpointPort] come from
     * [binding] - the EXACT manifest transport binding this candidate was
     * built from - never from `gateway.awg.endpointHost`/`endpointPort`
     * (the catalog). This is what makes a signed manifest's address
     * genuinely authoritative for the executed attempt: if the trusted
     * manifest ever advertises a rotated host/port for an endpoint, the
     * pinned [GatewayConfigSnapshot] for a new candidate reflects it
     * immediately, with no code change and no dependency on
     * `ProductionGatewayCatalog` being updated to match.
     *
     * [serverPublicKey]/[gatewayTunnelIp]/[profile] remain sourced from
     * [gateway] (the catalog compatibility lookup) because the current
     * manifest model does not carry them (see `EndpointTransportBinding`'s
     * own docs: `metadata` is generic but deliberately never holds key
     * material) - a real, honest scope boundary, not an oversight.
     * [clientTunnelIp] remains exclusively local per-device state, as
     * always.
     *
     * NOTE - this snapshot's `endpointHost`/`endpointPort` are ONLY ever
     * consumed by [net.pocvpn.client.vpn.VpnController]'s AWG execution
     * path (`GatewayConfigSnapshotValidator`/`TransportConfig.Awg`) - for
     * an XRAY_REALITY/TLS_TCP candidate this snapshot is still built (every
     * candidate carries one, per the "Candidate identity" invariant) and is
     * now truthfully manifest-derived too, but the ACTUAL connect-time
     * server address for those transports comes from the endpoint-scoped
     * `XrayProfileRepository`/`XrayTlsProfileRepository` (provisioned via
     * real control-plane activation), never from this snapshot - see
     * PROJECT_ARCHITECTURE.md's own note on this separate, still-unmoved
     * Xray address-authority boundary.
     */
    private fun snapshotFor(
        gateway: ProductionGatewayDescriptor,
        binding: EndpointTransportBinding,
        clientTunnelIp: String,
    ): GatewayConfigSnapshot = GatewayConfigSnapshot(
        endpointHost = binding.host,
        endpointPort = binding.port.toString(),
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
