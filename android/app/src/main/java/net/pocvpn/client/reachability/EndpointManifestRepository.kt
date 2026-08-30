package net.pocvpn.client.reachability

/** Outcome of offering a newly-downloaded candidate manifest to the repository. */
sealed class ManifestUpdateResult {
    data class Accepted(val manifest: EndpointManifest) : ManifestUpdateResult()
    data class Rejected(val reason: String) : ManifestUpdateResult()
}

/**
 * B11 - THE ONE place a manifest becomes "trusted for this session". Ties
 * together verification (signature/expiry/clock-skew - [verifier]),
 * durable last-known-good storage ([lkgStore]), and the embedded bootstrap
 * ([trustAnchors]/[bootstrapManifest]) into a single boundary, so no other
 * code needs to know the trust rules or storage details.
 *
 * Precedence on [trusted]: LKG if present, else the embedded bootstrap -
 * never "no manifest at all" while a bootstrap exists, matching the task's
 * "retain last-known-good ... embedded emergency/bootstrap manifest"
 * requirement. A newly downloaded manifest only ever reaches LKG via
 * [offer], which re-verifies it from scratch and enforces rollback
 * protection - this repository trusts nothing handed to it without
 * re-checking it itself.
 */
class EndpointManifestRepository(
    private val verifier: ManifestVerifier,
    private val trustAnchors: ManifestTrustAnchors,
    private val lkgStore: LastKnownGoodManifestStore,
    private val bootstrapManifest: SignedManifest,
    private val nowEpochMillis: () -> Long,
) {

    /** The manifest this session should actually use - see class docs for precedence. */
    fun trusted(): EndpointManifest {
        lkgStore.current()?.let { lkg ->
            if (verifier.verify(lkg, trustAnchors, nowEpochMillis()) is ManifestVerificationResult.Valid) {
                return lkg.manifest
            }
        }
        return bootstrapManifest.manifest
    }

    /** Where [trusted] is currently sourced from - for truthful diagnostics only, never a decision input elsewhere. */
    fun trustedSource(): ManifestSource {
        val lkg = lkgStore.current()
        return if (lkg != null && verifier.verify(lkg, trustAnchors, nowEpochMillis()) is ManifestVerificationResult.Valid) {
            ManifestSource.LAST_KNOWN_GOOD
        } else {
            ManifestSource.EMBEDDED_BOOTSTRAP
        }
    }

    /**
     * Offers a newly obtained (e.g. downloaded) manifest for adoption.
     * Verifies it fully, then enforces rollback protection against whatever
     * is currently trusted ([trusted]) - an invalid or older-version
     * candidate is rejected and the LKG store is left completely untouched.
     */
    fun offer(candidate: SignedManifest): ManifestUpdateResult {
        val verification = verifier.verify(candidate, trustAnchors, nowEpochMillis())
        if (verification is ManifestVerificationResult.Invalid) {
            return ManifestUpdateResult.Rejected(verification.reason)
        }
        if (!ManifestRollbackGuard.isAcceptableReplacement(trusted(), candidate.manifest)) {
            return ManifestUpdateResult.Rejected("candidate version ${candidate.manifest.manifestVersion} is not newer than the currently trusted manifest")
        }
        val stored = lkgStore.store(candidate)
        return if (stored) {
            ManifestUpdateResult.Accepted(candidate.manifest)
        } else {
            ManifestUpdateResult.Rejected("candidate version ${candidate.manifest.manifestVersion} rejected by rollback guard at storage time")
        }
    }
}

enum class ManifestSource {
    LAST_KNOWN_GOOD,
    EMBEDDED_BOOTSTRAP,
}
