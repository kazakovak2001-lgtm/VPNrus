package net.pocvpn.client.reachability

/** B50 observational dimensions. This model is never a path-selection authority. */
enum class FailureDomainDimension { OPERATOR, NETWORK, REGION, CDN, CONTROL_PLANE }
enum class StructuralDiversity { UNKNOWN, LOW, PARTIAL, STRONG }
enum class HistoricalReliability { UNKNOWN, POOR, MIXED, STABLE }
enum class AssessmentConfidence { INSUFFICIENT, LOW, MEDIUM, HIGH }
enum class OverallSurvivability { INSUFFICIENT_EVIDENCE, FRAGILE, LIMITED, RESILIENT }

enum class SurvivabilityReason {
    EMPTY_CANDIDATE_SET,
    SINGLE_CANDIDATE,
    FAILURE_DOMAIN_METADATA_INCOMPLETE,
    SHARED_OPERATOR_DOMAIN,
    SHARED_NETWORK_DOMAIN,
    SHARED_CONTROL_PLANE_DOMAIN,
    SHARED_CDN_DOMAIN,
    MULTIPLE_KNOWN_NETWORK_DOMAINS,
    PATH_CURRENTLY_UNREACHABLE,
    CURRENT_REACHABILITY_UNKNOWN,
    HISTORICAL_EVIDENCE_INSUFFICIENT,
    RECENT_FAILURE_STREAK,
    STABLE_LOCAL_HISTORY,
}

data class FailureDomainConcentration(
    val pathCount: Int,
    val uniqueKnownOperators: Int,
    val uniqueKnownNetworks: Int,
    val uniqueKnownRegions: Int,
    val uniqueKnownCdns: Int,
    val uniqueKnownControlPlanes: Int,
    val pathsWithUnknownDomains: Int,
)

data class CurrentReachabilitySummary(
    val reachable: Int,
    val degraded: Int,
    val unreachable: Int,
    val unknown: Int,
) {
    val usableNow: Int get() = reachable + degraded
}

data class HistoricalReliabilitySummary(
    val classification: HistoricalReliability,
    val successes: Int,
    val failures: Int,
    val observations: Int,
    val pathsWithHistory: Int,
    val pathsWithoutHistory: Int,
)

data class FailureDomainSurvivability(
    val dimension: FailureDomainDimension,
    val knownDomainCount: Int,
    val unknownPathCount: Int,
    /** Worst case across removal of any one known domain of this dimension. */
    val minimumRemainingUsablePaths: Int?,
)

data class PathSurvivabilityAssessment(
    val structuralDiversity: StructuralDiversity,
    val currentReachability: CurrentReachabilitySummary,
    val historicalReliability: HistoricalReliabilitySummary,
    val failureDomainConcentration: FailureDomainConcentration,
    val nMinusOne: List<FailureDomainSurvivability>,
    val confidence: AssessmentConfidence,
    val overallAssessment: OverallSurvivability,
    val reasons: List<SurvivabilityReason>,
)

data class SurvivabilityCandidate(
    val path: PathCandidate,
    /** Must already have been read for the current NetworkFingerprint. */
    val history: PathHistoryEntry? = null,
)

/**
 * Pure B50 diagnostic assessor. It consumes signed topology already admitted by the manifest
 * trust pipeline and locally measured state. It does not discover ASNs, score candidates, or
 * participate in Smart Connect / AutoGatewaySelector.
 */
object SurvivabilityAssessor {
    fun assess(candidates: List<SurvivabilityCandidate>): PathSurvivabilityAssessment {
        val paths = candidates.map { it.path }
        val domains = paths.associateWith(::domainsFor)
        val concentration = concentration(paths, domains)
        val reachability = currentReachability(paths)
        val history = history(candidates)
        val structural = structural(concentration)
        val nMinusOne = FailureDomainDimension.entries.map { dimension -> nMinusOne(dimension, paths, domains) }
        val reasons = reasons(paths, concentration, reachability, history)
        val confidence = confidence(paths.size, concentration.pathsWithUnknownDomains, reachability, history)
        val overall = when {
            paths.isEmpty() || confidence == AssessmentConfidence.INSUFFICIENT -> OverallSurvivability.INSUFFICIENT_EVIDENCE
            reachability.usableNow == 0 || nMinusOne.any { it.minimumRemainingUsablePaths == 0 } -> OverallSurvivability.FRAGILE
            structural == StructuralDiversity.STRONG && reachability.usableNow >= 2 && history.classification != HistoricalReliability.POOR -> OverallSurvivability.RESILIENT
            else -> OverallSurvivability.LIMITED
        }
        return PathSurvivabilityAssessment(structural, reachability, history, concentration, nMinusOne, confidence, overall, reasons)
    }

    private data class PathDomains(val values: Map<FailureDomainDimension, Set<FailureDomainId>>, val incomplete: Boolean)

    private fun domainsFor(path: PathCandidate): PathDomains {
        val values = FailureDomainDimension.entries.associateWith { linkedSetOf<FailureDomainId>() }.toMutableMap()
        var incomplete = false
        path.hops.forEachIndexed { index, hop ->
            val d = hop.binding.failureDomains()
            fun add(kind: FailureDomainDimension, value: FailureDomainId?) { if (value == null) incomplete = true else values.getValue(kind).add(value) }
            add(FailureDomainDimension.OPERATOR, d.operator)
            add(FailureDomainDimension.NETWORK, d.network)
            add(FailureDomainDimension.REGION, d.region)
            add(FailureDomainDimension.CONTROL_PLANE, d.controlPlane)
            val needsCdn = path is PathCandidate.Relayed && index == 0 && path.ingressKind == IngressKind.CDN_FRONTED
            if (needsCdn) add(FailureDomainDimension.CDN, d.cdn)
        }
        return PathDomains(values.mapValues { it.value.toSet() }, incomplete)
    }

    private fun concentration(paths: List<PathCandidate>, domains: Map<PathCandidate, PathDomains>): FailureDomainConcentration {
        fun unique(kind: FailureDomainDimension) = domains.values.flatMap { it.values.getValue(kind) }.toSet().size
        return FailureDomainConcentration(paths.size, unique(FailureDomainDimension.OPERATOR), unique(FailureDomainDimension.NETWORK),
            unique(FailureDomainDimension.REGION), unique(FailureDomainDimension.CDN), unique(FailureDomainDimension.CONTROL_PLANE),
            domains.values.count { it.incomplete })
    }

    private fun currentReachability(paths: List<PathCandidate>): CurrentReachabilitySummary {
        val states = paths.map { path -> path.hops.minByOrNull { reachabilityRank(it.reachability.state) }?.reachability?.state ?: ReachabilityState.UNKNOWN }
        return CurrentReachabilitySummary(states.count { it == ReachabilityState.REACHABLE }, states.count { it == ReachabilityState.DEGRADED },
            states.count { it == ReachabilityState.UNREACHABLE }, states.count { it == ReachabilityState.UNKNOWN })
    }

    private fun history(candidates: List<SurvivabilityCandidate>): HistoricalReliabilitySummary {
        val known = candidates.mapNotNull { it.history }
        val successes = known.sumOf { it.successCount.coerceAtMost(1024) }
        val failures = known.sumOf { it.failureCount.coerceAtMost(1024) }
        val observations = successes + failures
        val classification = when {
            observations == 0 -> HistoricalReliability.UNKNOWN
            known.any { it.consecutiveFailures >= 3 } || successes * 4 < observations -> HistoricalReliability.POOR
            observations >= 20 && successes * 4 >= observations * 3 -> HistoricalReliability.STABLE
            else -> HistoricalReliability.MIXED
        }
        return HistoricalReliabilitySummary(classification, successes, failures, observations, known.size, candidates.size - known.size)
    }

    private fun structural(c: FailureDomainConcentration): StructuralDiversity = when {
        c.pathCount < 2 -> if (c.pathCount == 0) StructuralDiversity.UNKNOWN else StructuralDiversity.LOW
        c.pathsWithUnknownDomains > 0 -> StructuralDiversity.UNKNOWN
        c.uniqueKnownOperators >= 2 && c.uniqueKnownNetworks >= 2 && c.uniqueKnownRegions >= 2 && c.uniqueKnownControlPlanes >= 2 -> StructuralDiversity.STRONG
        c.uniqueKnownOperators >= 2 || c.uniqueKnownNetworks >= 2 || c.uniqueKnownRegions >= 2 || c.uniqueKnownControlPlanes >= 2 -> StructuralDiversity.PARTIAL
        else -> StructuralDiversity.LOW
    }

    private fun nMinusOne(dimension: FailureDomainDimension, paths: List<PathCandidate>, domains: Map<PathCandidate, PathDomains>): FailureDomainSurvivability {
        val known = domains.values.flatMap { it.values.getValue(dimension) }.toSet()
        val unknown = paths.count { domains.getValue(it).values.getValue(dimension).isEmpty() }
        val usable = paths.filter(::isUsableNow)
        val remaining = known.minOfOrNull { lost -> usable.count { lost !in domains.getValue(it).values.getValue(dimension) } }
        return FailureDomainSurvivability(dimension, known.size, unknown, remaining)
    }

    private fun isUsableNow(path: PathCandidate): Boolean = path.hops.all { it.reachability.state == ReachabilityState.REACHABLE || it.reachability.state == ReachabilityState.DEGRADED }

    private fun confidence(pathCount: Int, unknownDomains: Int, reachability: CurrentReachabilitySummary, history: HistoricalReliabilitySummary): AssessmentConfidence {
        if (pathCount == 0) return AssessmentConfidence.INSUFFICIENT
        var points = 0
        if (unknownDomains == 0) points += 2
        if (reachability.unknown == 0) points += 2
        if (history.observations >= 20) points += 2 else if (history.observations > 0) points += 1
        return when (points) { 0, 1, 2 -> AssessmentConfidence.LOW; 3, 4, 5 -> AssessmentConfidence.MEDIUM; else -> AssessmentConfidence.HIGH }
    }

    private fun reasons(paths: List<PathCandidate>, c: FailureDomainConcentration, r: CurrentReachabilitySummary, h: HistoricalReliabilitySummary): List<SurvivabilityReason> = buildSet {
        if (paths.isEmpty()) add(SurvivabilityReason.EMPTY_CANDIDATE_SET)
        if (paths.size == 1) add(SurvivabilityReason.SINGLE_CANDIDATE)
        if (c.pathsWithUnknownDomains > 0) add(SurvivabilityReason.FAILURE_DOMAIN_METADATA_INCOMPLETE)
        if (paths.size > 1 && c.uniqueKnownOperators == 1) add(SurvivabilityReason.SHARED_OPERATOR_DOMAIN)
        if (paths.size > 1 && c.uniqueKnownNetworks == 1) add(SurvivabilityReason.SHARED_NETWORK_DOMAIN)
        if (paths.size > 1 && c.uniqueKnownControlPlanes == 1) add(SurvivabilityReason.SHARED_CONTROL_PLANE_DOMAIN)
        if (c.uniqueKnownCdns == 1 && paths.count { it is PathCandidate.Relayed && it.ingressKind == IngressKind.CDN_FRONTED } > 1) add(SurvivabilityReason.SHARED_CDN_DOMAIN)
        if (c.uniqueKnownNetworks >= 2) add(SurvivabilityReason.MULTIPLE_KNOWN_NETWORK_DOMAINS)
        if (r.unreachable > 0) add(SurvivabilityReason.PATH_CURRENTLY_UNREACHABLE)
        if (r.unknown > 0) add(SurvivabilityReason.CURRENT_REACHABILITY_UNKNOWN)
        if (h.observations == 0) add(SurvivabilityReason.HISTORICAL_EVIDENCE_INSUFFICIENT)
        if (h.classification == HistoricalReliability.POOR) add(SurvivabilityReason.RECENT_FAILURE_STREAK)
        if (h.classification == HistoricalReliability.STABLE) add(SurvivabilityReason.STABLE_LOCAL_HISTORY)
    }.toList().sortedBy { it.ordinal }

    private fun reachabilityRank(state: ReachabilityState): Int = when (state) {
        ReachabilityState.UNREACHABLE -> 0; ReachabilityState.DEGRADED -> 1; ReachabilityState.UNKNOWN -> 2; ReachabilityState.REACHABLE -> 3
    }
}

/** Point-in-time external evidence only; never merged into signed failure-domain topology. */
data class ObservedAsnEvidence(
    val endpointId: EndpointId,
    val role: EndpointRole,
    val publicAddress: String,
    val originAsn: Long,
    val announcedPrefix: String,
    val organization: String,
    val observedAtEpochMillis: Long,
    val source: String,
)
