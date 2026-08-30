package net.pocvpn.client.reachability

/**
 * B11 - truthful, read-only snapshot of the reachability fabric's current
 * state, for diagnostics surfaces only. Never includes signing keys, raw
 * credentials, or anything PathHistoryStore/manifest storage keep private -
 * see each field's own type for what it actually carries.
 *
 * OBSERVATIONAL ONLY: nothing reads this snapshot to change production
 * transport/gateway selection in this slice - see task scope's Smart Connect
 * boundary. It exists so the NEXT slice can feed [rankedPaths]'s winner into
 * SmartConnectDecisionEngine/TransportOrchestrator without inventing a new
 * shape at that point.
 */
data class ReachabilityDiagnosticsSnapshot(
    val manifestVersion: Int,
    val manifestSource: ManifestSource,
    val manifestExpiresAtEpochMillis: Long,
    val endpoints: List<EndpointDescriptor>,
    val reachability: List<EndpointReachability>,
    val pathCandidates: List<PathCandidate>,
    val rankedPaths: List<PathScorer.PathScoreResult>,
)

/**
 * B11 - assembles a [ReachabilityDiagnosticsSnapshot] from the repository +
 * already-computed reachability/candidates/scores. Pure aggregation, no I/O
 * of its own - callers (e.g. MainViewModel, mirroring its existing
 * restrictionClass()/transportScores() read-only accessor pattern) supply
 * freshly computed inputs on every read.
 */
object ReachabilityDiagnostics {
    fun snapshot(
        manifestRepository: EndpointManifestRepository,
        reachability: List<EndpointReachability>,
        pathCandidates: List<PathCandidate>,
        rankedPaths: List<PathScorer.PathScoreResult>,
    ): ReachabilityDiagnosticsSnapshot {
        val manifest = manifestRepository.trusted()
        return ReachabilityDiagnosticsSnapshot(
            manifestVersion = manifest.manifestVersion,
            manifestSource = manifestRepository.trustedSource(),
            manifestExpiresAtEpochMillis = manifest.expiresAtEpochMillis,
            endpoints = manifest.endpoints,
            reachability = reachability,
            pathCandidates = pathCandidates,
            rankedPaths = rankedPaths,
        )
    }
}
