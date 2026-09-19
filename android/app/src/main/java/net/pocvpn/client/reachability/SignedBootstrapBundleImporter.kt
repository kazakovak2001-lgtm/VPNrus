package net.pocvpn.client.reachability

/**
 * B56-2 - the exact, small set of import-level rejection categories this
 * importer actually produces. 1:1 with [ManifestUpdateRejectionKind] (see
 * [ManifestUpdateRejectionKind.toBootstrapBundleImportRejectionKind]) -
 * never invented beyond what [EndpointManifestRepository.offer] itself
 * already checks. This importer owns NO acceptance logic of its own; it only
 * relabels the repository's own typed rejection for bootstrap-import
 * diagnostics/UX (a later slice's concern, not this one's).
 */
enum class BootstrapBundleImportRejectionKind {
    BOOTSTRAP_BUNDLE_UNKNOWN_KEY,
    BOOTSTRAP_BUNDLE_CLOCK_UNCERTAIN,
    BOOTSTRAP_BUNDLE_EXPIRED,
    BOOTSTRAP_BUNDLE_SIGNATURE_INVALID,
    BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED,
}

/** Exhaustive 1:1 mapping - see [BootstrapBundleImportRejectionKind]'s own docs for why this is never anything but a relabeling. */
fun ManifestUpdateRejectionKind.toBootstrapBundleImportRejectionKind(): BootstrapBundleImportRejectionKind = when (this) {
    ManifestUpdateRejectionKind.UNKNOWN_SIGNING_KEY -> BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_UNKNOWN_KEY
    ManifestUpdateRejectionKind.CLOCK_SKEW -> BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_CLOCK_UNCERTAIN
    ManifestUpdateRejectionKind.EXPIRED -> BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_EXPIRED
    ManifestUpdateRejectionKind.INVALID_SIGNATURE -> BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_SIGNATURE_INVALID
    ManifestUpdateRejectionKind.ROLLBACK_OR_NOT_NEWER -> BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED
}

/**
 * Outcome of importing an out-of-band [SignedManifest] (a "SignedBootstrapBundle" -
 * see this class's own docs for why that is not a distinct artifact type).
 * [Malformed] exists only for [SignedBootstrapBundleImporter.importEncoded] -
 * [SignedBootstrapBundleImporter.import] can never produce it, since it is
 * handed an already-decoded [SignedManifest].
 */
sealed class BootstrapBundleImportResult {
    /**
     * [manifest] is the SAME [EndpointManifest] instance [EndpointManifestRepository.offer]
     * accepted and stored as ordinary last-known-good. [source] is
     * STRUCTURALLY, not just documentarily, always
     * [ManifestSource.IMPORTED_SIGNED_BOOTSTRAP] here - a computed property
     * with no backing constructor parameter, so no caller can construct an
     * [Accepted] claiming any other provenance (PR #93 review fix). It is
     * this import action's own delivery-provenance diagnostic, reported ONCE
     * at the moment of acceptance, and is NOT what [EndpointManifestRepository.trustedState]
     * reports afterward (that is, and remains, ordinary
     * [ManifestSource.LAST_KNOWN_GOOD] - see this class's and
     * [ManifestSource.IMPORTED_SIGNED_BOOTSTRAP]'s own docs for why
     * conflating the two would wrongly imply a second, higher-precedence
     * trust tier that does not exist).
     */
    data class Accepted(val manifest: EndpointManifest) : BootstrapBundleImportResult() {
        val source: ManifestSource get() = ManifestSource.IMPORTED_SIGNED_BOOTSTRAP
    }

    data class Rejected(val kind: BootstrapBundleImportRejectionKind, val reason: String) : BootstrapBundleImportResult()

    /** Decoding [SignedManifestCodec.decode] itself failed - the candidate never reached [EndpointManifestRepository.offer] at all. */
    data class Malformed(val reason: String) : BootstrapBundleImportResult()
}

/**
 * B56-2 - THE thin client-side boundary that lets an out-of-band
 * "SignedBootstrapBundle" (QR/file/package-delivered bytes) become trusted.
 *
 * By design, a `SignedBootstrapBundle` is NOT a new cryptographic artifact:
 * for this slice it is exactly [SignedManifest], signed by the SAME manifest
 * signing authority ([ManifestTrustAnchors]/[Ed25519ManifestVerifier]) as any
 * HTTPS-fetched manifest, decoded with the SAME [SignedManifestCodec], and
 * adopted through the SAME [EndpointManifestRepository.offer] every other
 * candidate already goes through (see `RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md`
 * section 16). This class owns exactly three things and NOTHING else:
 *  - classifying that a candidate arrived via out-of-band delivery (diagnostics only)
 *  - relabeling [ManifestUpdateResult]/[ManifestUpdateRejectionKind] into this
 *    slice's own result/rejection types (so bootstrap-import UX never has to
 *    know about the repository's internal vocabulary)
 *  - optionally decoding raw bytes with the existing, unmodified [SignedManifestCodec]
 *
 * It owns NO trust decision. It never re-implements signature/expiry/clock-
 * skew/rollback checking, never writes to [LastKnownGoodManifestStore]
 * directly, and never bypasses [EndpointManifestRepository.offer] for any
 * reason - see SignedBootstrapBundleImporterTest for an explicit proof that
 * every rejection path leaves the repository's existing trusted state
 * completely untouched, and that an activation-issuer key (a
 * [net.pocvpn.client.activation.ActivationIssuerTrustAnchors] key) can never
 * authorize a bootstrap manifest through this path.
 *
 * There is deliberately no `overrideHost`/`bootstrapUrl`/raw endpoint
 * parameter anywhere on this class: the ONLY network facts this importer can
 * ever cause to become trusted are the ones already inside the signed
 * [EndpointManifest] itself, verified by [repository]'s own [ManifestVerifier] -
 * exactly as true for any other [EndpointManifestRepository.offer] caller.
 */
class SignedBootstrapBundleImporter(private val repository: EndpointManifestRepository) {

    /**
     * Imports an already-decoded out-of-band candidate. Delegates directly
     * to [EndpointManifestRepository.offer] - see class docs. [kind] is
     * always non-null on [ManifestUpdateResult.Rejected] here (unlike the
     * legacy transport-failure wrapping case documented on
     * [ManifestUpdateResult.Rejected] itself) because this importer, like
     * [MultiOriginManifestDistributionClient], calls [EndpointManifestRepository.offer]
     * directly - never through that legacy wrapping path.
     */
    fun import(candidate: SignedManifest): BootstrapBundleImportResult =
        when (val result = repository.offer(candidate)) {
            is ManifestUpdateResult.Accepted -> BootstrapBundleImportResult.Accepted(result.manifest)
            is ManifestUpdateResult.Rejected -> {
                val kind = result.kind
                    ?: throw IllegalStateException("EndpointManifestRepository.offer() returned a null rejection kind for a direct call - this importer never goes through the legacy transport-failure wrapping path, so this indicates a repository invariant violation, not a real import failure")
                BootstrapBundleImportResult.Rejected(kind.toBootstrapBundleImportRejectionKind(), result.reason)
            }
        }

    /**
     * Optional raw-bytes entry point for the future QR/file/package layer
     * (not implemented in this slice - see `NovaActivationPackage`, deferred
     * to a later B56 slice). Uses the EXISTING [SignedManifestCodec.decode]
     * verbatim - no second binary parser for a [SignedManifest] is ever
     * created here. [SignedManifestCodec.decode] already fails closed before
     * any expensive work: it bounds the outer container's canonical/signature
     * length fields (so a malformed/huge-length-prefixed input is rejected
     * before allocating anything unbounded) and rejects ANY trailing bytes
     * (`stream.available() == 0` - the existing "exact-container" rule) - see
     * that function's own docs. This method therefore adds no additional
     * outer size bound of its own: doing so would either duplicate
     * [SignedManifestCodec]'s existing protection or require guessing a new
     * limit independent of the codec's own `MAX_CANONICAL_BYTES`/
     * `MAX_SIGNATURE_BYTES`, which is exactly the kind of second,
     * independently-drifting parser boundary this slice must not introduce.
     * A decode failure - malformed input OR trailing bytes - never reaches
     * [EndpointManifestRepository.offer] at all; it fails closed as
     * [BootstrapBundleImportResult.Malformed] before any trust decision.
     */
    fun importEncoded(bytes: ByteArray): BootstrapBundleImportResult {
        val decoded = try {
            SignedManifestCodec.decode(bytes)
        } catch (e: IllegalArgumentException) {
            return BootstrapBundleImportResult.Malformed(e.message ?: "malformed encoded bootstrap bundle")
        } catch (e: java.io.IOException) {
            return BootstrapBundleImportResult.Malformed(e.message ?: "malformed encoded bootstrap bundle")
        }
        return import(decoded)
    }
}
