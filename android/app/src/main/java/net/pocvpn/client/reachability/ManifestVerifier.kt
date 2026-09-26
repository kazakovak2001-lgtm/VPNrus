package net.pocvpn.client.reachability

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/** Non-secret identifier for a trusted public key, matching EndpointManifest.signingKeyId. */
data class TrustedKeyId(val value: String)

/**
 * The client's embedded trust roots: which public keys it accepts a manifest
 * signature from. Kept as its own type (not a bare Map) so the interfaces
 * for root/signing key separation exist even though this slice collapses
 * them - see class docs on [EmbeddedTrustAnchors] for why.
 */
interface ManifestTrustAnchors {
    fun publicKeyFor(keyId: TrustedKeyId): ByteArray?
}

class FixedManifestTrustAnchors(private val keys: Map<TrustedKeyId, ByteArray>) : ManifestTrustAnchors {
    override fun publicKeyFor(keyId: TrustedKeyId): ByteArray? = keys[keyId]
}

/** B20 - the exact, small set of rejection categories this verifier actually produces (see each [Ed25519ManifestVerifier.verify] return site) - never invented beyond what the implementation checks. */
enum class ManifestVerificationFailureKind {
    UNKNOWN_SIGNING_KEY,
    CLOCK_SKEW,
    EXPIRED,
    INVALID_SIGNATURE,
}

sealed class ManifestVerificationResult {
    object Valid : ManifestVerificationResult()
    /** [kind] is the typed category a caller should branch on; [reason] is the human-readable detail for diagnostics only - see [ManifestVerificationFailureKind]'s own docs for why this is never inferred by parsing [reason] elsewhere. */
    data class Invalid(val kind: ManifestVerificationFailureKind, val reason: String) : ManifestVerificationResult()
}

/**
 * B11 - verifies a [SignedManifest] against embedded trust roots. Pure/no
 * I/O: given the same inputs and [nowEpochMillis], always the same result.
 * Every rejection reason is distinct (see ManifestVerifierTest) so callers
 * never have to guess why a manifest was rejected.
 */
interface ManifestVerifier {
    fun verify(signed: SignedManifest, trustAnchors: ManifestTrustAnchors, nowEpochMillis: Long): ManifestVerificationResult
}

/**
 * Real Ed25519 verification. [clockSkewToleranceMillis] bounds how far into
 * the future [EndpointManifest.issuedAtEpochMillis] may be before it's
 * rejected as implausible (a manifest "issued" after the device's own clock
 * is either a clock skew or a forged/replayed value - either way it must not
 * be trusted blindly).
 */
class Ed25519ManifestVerifier(
    private val clockSkewToleranceMillis: Long = DEFAULT_CLOCK_SKEW_TOLERANCE_MS,
) : ManifestVerifier {

    override fun verify(signed: SignedManifest, trustAnchors: ManifestTrustAnchors, nowEpochMillis: Long): ManifestVerificationResult {
        val manifest = signed.manifest
        val publicKeyBytes = trustAnchors.publicKeyFor(TrustedKeyId(manifest.signingKeyId))
            ?: return ManifestVerificationResult.Invalid(ManifestVerificationFailureKind.UNKNOWN_SIGNING_KEY, "unknown signing key id: ${manifest.signingKeyId}")

        if (manifest.issuedAtEpochMillis > nowEpochMillis + clockSkewToleranceMillis) {
            return ManifestVerificationResult.Invalid(ManifestVerificationFailureKind.CLOCK_SKEW, "issuedAt is implausibly in the future")
        }
        if (manifest.expiresAtEpochMillis <= nowEpochMillis) {
            return ManifestVerificationResult.Invalid(ManifestVerificationFailureKind.EXPIRED, "manifest has expired")
        }

        // Schema 2 (B-WL-R6): the exact received canonical bytes. Schema 1:
        // the re-canonicalization, which its strict decoder guarantees is
        // byte-identical to what was received.
        val signedBytes = signed.signedCanonicalBytes
        val canonical = signedBytes ?: ManifestCanonicalizer.canonicalBytes(manifest)
        val signatureValid = try {
            verifyEd25519(publicKeyBytes, canonical, signed.signature)
        } catch (e: IllegalArgumentException) {
            false
        }
        if (!signatureValid) return ManifestVerificationResult.Invalid(ManifestVerificationFailureKind.INVALID_SIGNATURE, "signature verification failed")

        // Only now, over bytes whose signature just verified, is the schema-2
        // interpretation (re)derived; the candidate [manifest] is trusted only
        // if it is exactly that interpretation.
        if (signedBytes != null) {
            val interpreted = try {
                ManifestSchema2Codec.decode(signedBytes)
            } catch (e: IllegalArgumentException) {
                null
            } catch (e: java.io.IOException) {
                null
            }
            if (interpreted == null || interpreted.manifest != manifest || interpreted.tolerance != signed.tolerance) {
                return ManifestVerificationResult.Invalid(ManifestVerificationFailureKind.INVALID_SIGNATURE, "manifest does not match its signed schema-2 bytes")
            }
        }

        return ManifestVerificationResult.Valid
    }

    private fun verifyEd25519(publicKeyBytes: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        require(publicKeyBytes.size == Ed25519PublicKeyParameters.KEY_SIZE) { "invalid Ed25519 public key length: ${publicKeyBytes.size}" }
        require(signature.size == 64) { "invalid Ed25519 signature length: ${signature.size}" }
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKeyBytes, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }

    companion object {
        const val DEFAULT_CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000L
    }
}
