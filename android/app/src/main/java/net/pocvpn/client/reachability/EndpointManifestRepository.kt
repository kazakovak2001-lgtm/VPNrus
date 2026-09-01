package net.pocvpn.client.reachability

/**
 * B20 - the exact, small set of rejection categories [EndpointManifestRepository.offer]
 * actually produces: the first four mirror [ManifestVerificationFailureKind]
 * 1:1 (see [toUpdateRejectionKind]); [ROLLBACK_OR_NOT_NEWER] is added by
 * [EndpointManifestRepository.offer] itself for both rollback-guard rejection
 * sites (candidate not newer than currently trusted; candidate rejected at
 * storage time by the same guard). Never invented beyond what [offer]
 * actually checks.
 */
enum class ManifestUpdateRejectionKind {
    UNKNOWN_SIGNING_KEY,
    CLOCK_SKEW,
    EXPIRED,
    INVALID_SIGNATURE,
    ROLLBACK_OR_NOT_NEWER,
}

/** Exhaustive 1:1 mapping - a verifier rejection and the repository's own typed rejection describe the SAME four categories, just at two different call sites. */
fun ManifestVerificationFailureKind.toUpdateRejectionKind(): ManifestUpdateRejectionKind = when (this) {
    ManifestVerificationFailureKind.UNKNOWN_SIGNING_KEY -> ManifestUpdateRejectionKind.UNKNOWN_SIGNING_KEY
    ManifestVerificationFailureKind.CLOCK_SKEW -> ManifestUpdateRejectionKind.CLOCK_SKEW
    ManifestVerificationFailureKind.EXPIRED -> ManifestUpdateRejectionKind.EXPIRED
    ManifestVerificationFailureKind.INVALID_SIGNATURE -> ManifestUpdateRejectionKind.INVALID_SIGNATURE
}

/** Outcome of offering a newly-downloaded candidate manifest to the repository. */
sealed class ManifestUpdateResult {
    data class Accepted(val manifest: EndpointManifest) : ManifestUpdateResult()

    /**
     * [kind] is ALWAYS set (non-null) when this [Rejected] came from
     * [EndpointManifestRepository.offer] itself - the repository is the ONE
     * acceptance authority and always knows exactly why it rejected a
     * candidate (see [ManifestUpdateRejectionKind]'s own docs). It is null
     * ONLY for the one pre-existing, non-B20 case where [ManifestDistributionClient.refresh]
     * wraps a transport-level [ManifestFetchResult.Failed] into a Rejected
     * without ever reaching [EndpointManifestRepository.offer] at all - there
     * is genuinely no verification/rollback category to report, because
     * verification never ran. [MultiOriginManifestDistributionClient] never
     * hits that null path: it calls [EndpointManifestRepository.offer]
     * directly and classifies fetch failures from [ManifestFetchResult.Failed.kind]
     * instead - see its own docs.
     */
    data class Rejected(val kind: ManifestUpdateRejectionKind?, val reason: String) : ManifestUpdateResult()
}

/**
 * What this session currently trusts, or the explicit fact that nothing
 * verifies. NEVER collapse [NoneTrusted] into a null/absent-looking value
 * elsewhere - every caller of [EndpointManifestRepository.trustedState] must
 * handle it, matching the "bootstrap is never an unverified fallback" rule:
 * an embedded manifest that fails verification is exactly as untrusted as no
 * manifest at all, never silently substituted anyway just because it shipped
 * inside the APK.
 */
sealed class TrustedManifestState {
    data class Trusted(val manifest: EndpointManifest, val source: ManifestSource) : TrustedManifestState()

    /** LKG absent-or-invalid AND the embedded bootstrap itself failed verification - the fail-closed state. */
    data class NoneTrusted(val bootstrapRejectionReason: String) : TrustedManifestState()
}

/**
 * B11 - THE ONE place a manifest becomes "trusted for this session". Ties
 * together verification (signature/expiry/clock-skew - [verifier]),
 * durable last-known-good storage ([lkgStore]), and the embedded bootstrap
 * ([trustAnchors]/[bootstrapManifest]) into a single boundary, so no other
 * code needs to know the trust rules or storage details.
 *
 * Precedence in [trustedState]:
 *  1. LKG, IF it verifies -> Trusted(lkg, LAST_KNOWN_GOOD)
 *  2. else the embedded bootstrap, IF IT ALSO verifies against the SAME
 *     [verifier]/[trustAnchors] -> Trusted(bootstrap, EMBEDDED_BOOTSTRAP).
 *     The bootstrap is compiled into the APK, but that alone never makes it
 *     trusted - it goes through the identical signature/expiry/clock-skew
 *     check as any other candidate (see EmbeddedBootstrapManifestTest for
 *     why this bootstrap actually does verify in production, and
 *     EndpointManifestRepositoryTest for proof a BROKEN one does not).
 *  3. else -> [TrustedManifestState.NoneTrusted] - the explicit fail-closed
 *     state. There is deliberately no code path that returns "some manifest"
 *     without it having passed [verifier] at the point of use.
 *
 * A newly downloaded manifest only ever reaches LKG via [offer], which
 * re-verifies it from scratch and enforces rollback protection - this
 * repository trusts nothing handed to it without re-checking it itself.
 */
class EndpointManifestRepository(
    private val verifier: ManifestVerifier,
    private val trustAnchors: ManifestTrustAnchors,
    private val lkgStore: LastKnownGoodManifestStore,
    private val bootstrapManifest: SignedManifest,
    private val nowEpochMillis: () -> Long,
) {

    /** See class docs for the exact precedence and why [TrustedManifestState.NoneTrusted] is a real, reachable outcome. */
    fun trustedState(): TrustedManifestState {
        lkgStore.current()?.let { lkg ->
            if (verifier.verify(lkg, trustAnchors, nowEpochMillis()) is ManifestVerificationResult.Valid) {
                return TrustedManifestState.Trusted(lkg.manifest, ManifestSource.LAST_KNOWN_GOOD)
            }
        }
        val bootstrapVerification = verifier.verify(bootstrapManifest, trustAnchors, nowEpochMillis())
        return if (bootstrapVerification is ManifestVerificationResult.Valid) {
            TrustedManifestState.Trusted(bootstrapManifest.manifest, ManifestSource.EMBEDDED_BOOTSTRAP)
        } else {
            val reason = (bootstrapVerification as ManifestVerificationResult.Invalid).reason
            TrustedManifestState.NoneTrusted(bootstrapRejectionReason = reason)
        }
    }

    /** Convenience accessor for callers that only need the manifest itself - null exactly when [trustedState] is [TrustedManifestState.NoneTrusted]. Never a value that hasn't passed [verifier]. */
    fun trusted(): EndpointManifest? = (trustedState() as? TrustedManifestState.Trusted)?.manifest

    /** Where [trusted] is currently sourced from - null exactly when nothing is trusted. Truthful diagnostics only, never a decision input elsewhere. */
    fun trustedSource(): ManifestSource? = (trustedState() as? TrustedManifestState.Trusted)?.source

    /**
     * Offers a newly obtained (e.g. downloaded) manifest for adoption.
     * Verifies it fully, then enforces rollback protection against whatever
     * is CURRENTLY TRUSTED ([trustedState]) - an invalid or older-version
     * candidate is rejected and the LKG store is left completely untouched.
     * When nothing is currently trusted ([TrustedManifestState.NoneTrusted]),
     * any validly-signed, non-expired candidate is an acceptable replacement
     * (there is nothing to roll back from) - the SAME rule
     * [ManifestRollbackGuard.isAcceptableReplacement] already applies for a
     * null "current".
     */
    fun offer(candidate: SignedManifest): ManifestUpdateResult {
        val verification = verifier.verify(candidate, trustAnchors, nowEpochMillis())
        if (verification is ManifestVerificationResult.Invalid) {
            return ManifestUpdateResult.Rejected(verification.kind.toUpdateRejectionKind(), verification.reason)
        }
        val currentlyTrusted = (trustedState() as? TrustedManifestState.Trusted)?.manifest
        if (!ManifestRollbackGuard.isAcceptableReplacement(currentlyTrusted, candidate.manifest)) {
            return ManifestUpdateResult.Rejected(
                ManifestUpdateRejectionKind.ROLLBACK_OR_NOT_NEWER,
                "candidate version ${candidate.manifest.manifestVersion} is not newer than the currently trusted manifest",
            )
        }
        val stored = lkgStore.store(candidate)
        return if (stored) {
            ManifestUpdateResult.Accepted(candidate.manifest)
        } else {
            ManifestUpdateResult.Rejected(
                ManifestUpdateRejectionKind.ROLLBACK_OR_NOT_NEWER,
                "candidate version ${candidate.manifest.manifestVersion} rejected by rollback guard at storage time",
            )
        }
    }
}

enum class ManifestSource {
    LAST_KNOWN_GOOD,
    EMBEDDED_BOOTSTRAP,
}
