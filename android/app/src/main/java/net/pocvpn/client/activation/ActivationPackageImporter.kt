package net.pocvpn.client.activation

import net.pocvpn.client.reachability.BootstrapBundleImportRejectionKind
import net.pocvpn.client.reachability.BootstrapBundleImportResult
import net.pocvpn.client.reachability.SignedBootstrapBundleImporter
import net.pocvpn.client.reachability.SignedManifestCodec
import java.security.MessageDigest

/** Every way a package is refused locally, BEFORE any credential use. Non-secret by construction. */
enum class ActivationPackageRejectionKind {
    PACKAGE_MALFORMED,
    PACKAGE_VERSION_UNSUPPORTED,
    LEVEL2_NOT_SUPPORTED,
    SIGNATURE_INVALID,
    ISSUER_UNKNOWN,
    EXPIRED,
    NOT_YET_VALID,
    CLOCK_UNCERTAIN,
    ALREADY_REDEEMED,
    BOOTSTRAP_BUNDLE_MISMATCH,
    BOOTSTRAP_BUNDLE_INVALID,
}

/** What happened to the package's network facts - reported explicitly, never implied. */
enum class BootstrapStagingStatus {
    /** Package carries no bundle: activation needs an already-known reachable control plane. */
    NOT_INCLUDED,
    /** The envelope names a bundle the package does not carry - nothing staged. */
    REFERENCED_BUT_NOT_INCLUDED,
    /** Bundle verified and adopted by the existing EndpointManifestRepository (new LKG). */
    STAGED,
    /** Bundle verified structurally but the device already trusts the same or a newer manifest. */
    ALREADY_CURRENT_OR_NEWER,
}

sealed class ActivationPackageImportResult {
    /**
     * Envelope cryptographically verified against the activation-issuer
     * trust anchors, within its validity window, not previously redeemed on
     * this device, and any carried bundle handed to the existing manifest
     * repository. Only from this point may [envelope]'s credential be used.
     */
    class Verified(
        val envelope: ActivationEnvelope,
        val bootstrap: BootstrapStagingStatus,
        val stagedManifestVersion: Int?,
    ) : ActivationPackageImportResult() {
        override fun toString(): String = "Verified(activationId=${envelope.activationId.value}, bootstrap=$bootstrap, stagedManifestVersion=$stagedManifestVersion)"
    }

    data class Rejected(val kind: ActivationPackageRejectionKind) : ActivationPackageImportResult()
}

/**
 * B56-5 - the ONE Android entry point that turns an untrusted
 * [ActivationPackageInput] into a verified [ActivationEnvelope]. Pure
 * JVM (no Android framework), so every ordering guarantee below is unit
 * tested. Reuses, never re-implements:
 * - [ActivationPackageParser] -> the existing [ActivationEnvelopeCodec];
 * - the existing [ActivationEnvelopeVerifier] against [trustAnchors]
 *   (production: [ProductionActivationIssuerTrustAnchors] - a trust domain
 *   disjoint from manifest trust anchors);
 * - the existing [SignedBootstrapBundleImporter] -> `EndpointManifestRepository.offer()`
 *   for the bundle (manifest signature, manifest trust anchors, expiry,
 *   rollback guard and LKG persistence all unchanged - there is no second
 *   manifest verifier or repository).
 *
 * Order (each step fails closed and stops):
 * 1. structural parse; 2. envelope signature + issuer + validity window;
 * 3. local replay guard; 4. bundle <-> `bootstrapBundleRef` binding
 * (exact-byte SHA-256 + manifest version); 5. bundle offer to the existing
 * repository. The credential is never read before step 2 succeeds, and a
 * rejected package never reaches activation (the caller only activates on
 * [ActivationPackageImportResult.Verified]).
 *
 * A bundle that the repository rejects for any reason other than "not
 * newer" rejects the WHOLE package (a tampered/expired/foreign-key bundle
 * means the package as delivered is not what the issuer produced). "Not
 * newer" is benign - the device already has equal-or-fresher network facts.
 */
class ActivationPackageImporter(
    private val trustAnchors: ActivationIssuerTrustAnchors,
    private val bundleImporter: SignedBootstrapBundleImporter,
    private val replayGuard: ActivationReplayGuard,
    private val verifier: ActivationEnvelopeVerifier = Ed25519ActivationEnvelopeVerifier(),
) {
    fun import(input: ActivationPackageInput, nowEpochMillis: Long): ActivationPackageImportResult {
        val pkg = when (val parsed = ActivationPackageParser.parse(input)) {
            is ActivationPackageParseResult.Failure -> return reject(parsed.failure.toRejectionKind())
            is ActivationPackageParseResult.Success -> parsed.pkg
        }

        val envelope = when (val verified = verifier.verify(pkg.signedEnvelope, trustAnchors, nowEpochMillis)) {
            is ActivationEnvelopeVerificationResult.Invalid -> return reject(verified.kind.toRejectionKind())
            is ActivationEnvelopeVerificationResult.Valid -> verified.envelope
        }

        if (replayGuard.isRedeemed(envelope)) return reject(ActivationPackageRejectionKind.ALREADY_REDEEMED)

        val bundle = pkg.bootstrapBundle
        val ref = envelope.bootstrapBundleRef
        if (bundle == null) {
            val status = if (ref != null) BootstrapStagingStatus.REFERENCED_BUT_NOT_INCLUDED else BootstrapStagingStatus.NOT_INCLUDED
            return ActivationPackageImportResult.Verified(envelope, status, null)
        }

        if (ref != null) {
            val hash = MessageDigest.getInstance("SHA-256").digest(bundle)
            if (!MessageDigest.isEqual(hash, ref.contentHash)) return reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_MISMATCH)
            val bundleVersion = try {
                SignedManifestCodec.decode(bundle).manifest.manifestVersion
            } catch (e: IllegalArgumentException) {
                return reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID)
            } catch (e: java.io.IOException) {
                return reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID)
            }
            if (bundleVersion != ref.manifestVersion) return reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_MISMATCH)
        }

        return when (val imported = bundleImporter.importEncoded(bundle)) {
            is BootstrapBundleImportResult.Accepted ->
                ActivationPackageImportResult.Verified(envelope, BootstrapStagingStatus.STAGED, imported.manifest.manifestVersion)
            is BootstrapBundleImportResult.Rejected ->
                if (imported.kind == BootstrapBundleImportRejectionKind.BOOTSTRAP_BUNDLE_ROLLBACK_REJECTED) {
                    ActivationPackageImportResult.Verified(envelope, BootstrapStagingStatus.ALREADY_CURRENT_OR_NEWER, null)
                } else {
                    reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID)
                }
            is BootstrapBundleImportResult.Malformed -> reject(ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID)
        }
    }

    /** Called by the runtime only after the existing activation flow reported success. */
    fun markRedeemed(envelope: ActivationEnvelope, nowEpochMillis: Long) = replayGuard.markRedeemed(envelope, nowEpochMillis)

    private fun reject(kind: ActivationPackageRejectionKind) = ActivationPackageImportResult.Rejected(kind)
}

internal fun ActivationPackageParseFailure.toRejectionKind(): ActivationPackageRejectionKind = when (this) {
    is ActivationPackageParseFailure.UnsupportedSchemaVersion -> ActivationPackageRejectionKind.PACKAGE_VERSION_UNSUPPORTED
    ActivationPackageParseFailure.Level2NotSupported -> ActivationPackageRejectionKind.LEVEL2_NOT_SUPPORTED
    is ActivationPackageParseFailure.EnvelopeMalformed -> failure.toFailureKind().toRejectionKind()
    ActivationPackageParseFailure.NotAPackage,
    ActivationPackageParseFailure.Malformed,
    ActivationPackageParseFailure.TooLarge -> ActivationPackageRejectionKind.PACKAGE_MALFORMED
}

internal fun ActivationEnvelopeFailureKind.toRejectionKind(): ActivationPackageRejectionKind = when (this) {
    ActivationEnvelopeFailureKind.PACKAGE_MALFORMED -> ActivationPackageRejectionKind.PACKAGE_MALFORMED
    ActivationEnvelopeFailureKind.PACKAGE_VERSION_UNSUPPORTED -> ActivationPackageRejectionKind.PACKAGE_VERSION_UNSUPPORTED
    ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID -> ActivationPackageRejectionKind.SIGNATURE_INVALID
    ActivationEnvelopeFailureKind.ISSUER_KEY_UNKNOWN -> ActivationPackageRejectionKind.ISSUER_UNKNOWN
    ActivationEnvelopeFailureKind.PACKAGE_EXPIRED -> ActivationPackageRejectionKind.EXPIRED
    ActivationEnvelopeFailureKind.PACKAGE_NOT_YET_VALID -> ActivationPackageRejectionKind.NOT_YET_VALID
    ActivationEnvelopeFailureKind.CLOCK_UNCERTAIN -> ActivationPackageRejectionKind.CLOCK_UNCERTAIN
}

/** Outcome of one attempt through the EXISTING activateDevice() flow, as the package flow needs it. */
enum class ActivationAttemptOutcome { SUCCEEDED, NETWORK_UNAVAILABLE, FAILED }

/**
 * B56-5 runtime state for the package flow. The existing
 * `ProvisioningUiState` continues to describe the underlying
 * `/v1/activate` call itself (Revoked/Expired/DeviceLimitReached/...);
 * this adds only what is package-specific.
 */
sealed class ActivationPackageUiState {
    object Idle : ActivationPackageUiState()
    object Verifying : ActivationPackageUiState()
    data class Activating(val bootstrap: BootstrapStagingStatus) : ActivationPackageUiState()
    data class Succeeded(val bootstrap: BootstrapStagingStatus) : ActivationPackageUiState()
    data class Rejected(val kind: ActivationPackageRejectionKind) : ActivationPackageUiState()

    /**
     * Verified locally, but `/v1/activate` could not be reached. The
     * verified envelope is held IN MEMORY ONLY for MainViewModel.retryPendingActivationPackage()
     * (never persisted - an app restart requires re-importing the package).
     * [bootstrap] says whether the package's own network facts were staged.
     */
    data class NetworkRequired(val bootstrap: BootstrapStagingStatus) : ActivationPackageUiState()

    /** Reached the server, which refused (see ProvisioningUiState for which). */
    object ActivationFailed : ActivationPackageUiState()

    /** No importer wired (e.g. a test ViewModel) - fail closed, never fall back to raw-credential parsing. */
    object Unavailable : ActivationPackageUiState()
}
