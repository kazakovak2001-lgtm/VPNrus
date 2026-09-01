package net.pocvpn.client.reachability

/**
 * B20 - one HTTPS transport option for fetching the manifest. [id] is a
 * label for observability only (e.g. "frankfurt") - it carries NO trust
 * weight of any kind. An origin is transport availability, never a trust
 * authority: every candidate fetched from it still passes through the SAME
 * [EndpointManifestRepository.offer] signature/expiry/rollback boundary as
 * any other candidate - see [MultiOriginManifestDistributionClient].
 */
data class ManifestOrigin(val id: String, val url: String)

/**
 * B20 - parses/validates the developer- or build-config-supplied comma
 * separated origin URL list into a deterministically ordered, deduplicated
 * [ManifestOrigin] list. Fail-safe: a blank or malformed entry is silently
 * dropped rather than producing a broken origin (a malformed URL would just
 * fail every fetch anyway - dropping it up front is a clearer failure mode,
 * matching HttpsRemoteManifestFetcher's own "never construct against
 * obviously-unusable input" discipline for a blank MANIFEST_URL).
 */
object ManifestOriginConfig {
    fun parse(rawCommaSeparated: String): List<ManifestOrigin> {
        val seenUrls = LinkedHashSet<String>()
        val origins = mutableListOf<ManifestOrigin>()
        rawCommaSeparated.split(",").forEach { entry ->
            val url = entry.trim()
            if (url.isEmpty()) return@forEach
            if (!isHttpsUrl(url)) return@forEach
            if (seenUrls.add(url)) {
                origins.add(ManifestOrigin(id = idFor(url), url = url))
            }
        }
        return origins
    }

    private fun isHttpsUrl(url: String): Boolean = try {
        val parsed = java.net.URL(url)
        parsed.protocol == "https" && !parsed.host.isNullOrBlank()
    } catch (e: java.net.MalformedURLException) {
        false
    }

    /** Host-based id (e.g. "152.70.43.1") - callers that want the friendly "frankfurt"/"stockholm" labels resolve them separately (see AppRoot's diagnostics presentation), never baked in here since this type has no business knowing about ProductionGatewayCatalog. */
    private fun idFor(url: String): String = try {
        java.net.URL(url).host ?: url
    } catch (e: java.net.MalformedURLException) {
        url
    }
}

/** Typed, coarse evidence bucket for one origin's outcome this refresh - see [MultiOriginManifestDistributionClient.refresh]'s own docs for how each is derived from the existing [ManifestFetchResult]/[ManifestUpdateResult] reason strings (deliberately NOT a second crypto-result vocabulary - just a classification of the one that already exists). */
enum class ManifestOriginOutcomeKind {
    NETWORK_ERROR,
    TLS_ERROR,
    HTTP_ERROR,
    INVALID_SIGNATURE,
    EXPIRED,
    ROLLBACK_OR_NOT_NEWER,
    ACCEPTED,
}

data class ManifestOriginOutcome(val kind: ManifestOriginOutcomeKind, val detail: String)

data class ManifestOriginResult(val origin: ManifestOrigin, val outcome: ManifestOriginOutcome)

/**
 * B20 - the result of one multi-origin refresh: per-origin evidence (for
 * diagnostics - see AppRoot) plus the final [ManifestUpdateResult] this
 * refresh actually produced (null only when zero origins are configured,
 * mirroring [ManifestDistributionClient]'s own "unconfigured -> no-op"
 * contract). [finalOutcome] being Rejected does NOT mean trust was lost -
 * [EndpointManifestRepository.trustedState] is the truthful source for
 * what's currently trusted (LKG survives untouched on an all-origins-fail
 * refresh, exactly as it always has for the single-origin case).
 */
data class MultiOriginRefreshResult(
    val perOrigin: List<ManifestOriginResult>,
    val finalOutcome: ManifestUpdateResult?,
)

/**
 * B20 - tries every configured origin, in order, every refresh (never stops
 * early on the first ACCEPTED): with a small fixed origin set, offering
 * every origin's candidate to the SAME [EndpointManifestRepository] is what
 * actually implements "highest valid version wins" for free - [offer]
 * already enforces rollback against whatever is CURRENTLY trusted at each
 * call, so a later origin in the same refresh that returns a strictly newer
 * valid manifest still gets adopted even after an earlier origin's
 * (also-valid, older) candidate was already accepted. Each origin's fetch
 * uses the SAME real [ManifestDistributionClient]-shaped fetch-then-offer
 * pipeline (via [fetcherFor]) - no parallel/fake trust path of any kind.
 *
 * Origin identity is never a trust decision - offer() re-verifies every
 * candidate from scratch regardless of which origin produced it, so a
 * hostile/misconfigured origin serving modified bytes fails verification
 * exactly like any other invalid candidate would (see
 * [EndpointManifestRepository.offer]'s own docs).
 */
class MultiOriginManifestDistributionClient(
    private val origins: List<ManifestOrigin>,
    private val repository: EndpointManifestRepository,
    private val fetcherFor: (ManifestOrigin) -> RemoteManifestFetcher = { HttpsRemoteManifestFetcher(it.url) },
) {
    suspend fun refresh(): MultiOriginRefreshResult {
        val perOrigin = mutableListOf<ManifestOriginResult>()
        var lastAccepted: ManifestUpdateResult.Accepted? = null
        var lastRejected: ManifestUpdateResult.Rejected? = null

        for (origin in origins) {
            when (val fetchResult = fetcherFor(origin).fetch()) {
                is ManifestFetchResult.Failed -> {
                    perOrigin.add(ManifestOriginResult(origin, classifyFetchFailure(fetchResult.reason)))
                }
                is ManifestFetchResult.Fetched -> {
                    when (val offerResult = repository.offer(fetchResult.signed)) {
                        is ManifestUpdateResult.Accepted -> {
                            lastAccepted = offerResult
                            perOrigin.add(
                                ManifestOriginResult(
                                    origin,
                                    ManifestOriginOutcome(
                                        ManifestOriginOutcomeKind.ACCEPTED,
                                        "accepted version ${offerResult.manifest.manifestVersion}",
                                    ),
                                ),
                            )
                        }
                        is ManifestUpdateResult.Rejected -> {
                            lastRejected = offerResult
                            perOrigin.add(ManifestOriginResult(origin, classifyRejection(offerResult.reason)))
                        }
                    }
                }
            }
        }

        val finalOutcome: ManifestUpdateResult? = when {
            origins.isEmpty() -> null
            lastAccepted != null -> lastAccepted
            lastRejected != null -> lastRejected
            else -> ManifestUpdateResult.Rejected(perOrigin.lastOrNull()?.outcome?.detail ?: "no origin produced a candidate")
        }
        return MultiOriginRefreshResult(perOrigin, finalOutcome)
    }

    private fun classifyFetchFailure(reason: String): ManifestOriginOutcome = when {
        reason.startsWith("TLS error") -> ManifestOriginOutcome(ManifestOriginOutcomeKind.TLS_ERROR, reason)
        reason.startsWith("unexpected HTTP status") -> ManifestOriginOutcome(ManifestOriginOutcomeKind.HTTP_ERROR, reason)
        else -> ManifestOriginOutcome(ManifestOriginOutcomeKind.NETWORK_ERROR, reason)
    }

    private fun classifyRejection(reason: String): ManifestOriginOutcome = when {
        reason == "manifest has expired" -> ManifestOriginOutcome(ManifestOriginOutcomeKind.EXPIRED, reason)
        reason.startsWith("candidate version") -> ManifestOriginOutcome(ManifestOriginOutcomeKind.ROLLBACK_OR_NOT_NEWER, reason)
        else -> ManifestOriginOutcome(ManifestOriginOutcomeKind.INVALID_SIGNATURE, reason)
    }
}
