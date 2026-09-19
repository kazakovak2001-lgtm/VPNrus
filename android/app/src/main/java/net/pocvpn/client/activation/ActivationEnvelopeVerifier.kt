package net.pocvpn.client.activation

import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * B56-1 - the small, CLOSED set of architecture-level rejection categories
 * an [ActivationEnvelopeVerifier]/[ActivationEnvelopeCodec] pipeline
 * actually produces. Mirrors
 * [net.pocvpn.client.reachability.ManifestVerificationFailureKind]'s
 * discipline: never invented beyond what the implementation checks, and
 * never a place to leak the dozens of internal [ActivationEnvelopeParseFailure]
 * details - those exist for tests/diagnostics only.
 *
 * `PACKAGE_EXPIRED` here is ENVELOPE expiry ([ActivationEnvelope.expiresAtEpochMillis]),
 * never to be conflated with a future server-side `ACTIVATION_EXPIRED`
 * result (the activation's own live entitlement expiry - a completely
 * different, not-yet-implemented concept).
 */
enum class ActivationEnvelopeFailureKind {
    PACKAGE_MALFORMED,
    PACKAGE_VERSION_UNSUPPORTED,
    PACKAGE_SIGNATURE_INVALID,
    ISSUER_KEY_UNKNOWN,
    PACKAGE_EXPIRED,
    PACKAGE_NOT_YET_VALID,
    CLOCK_UNCERTAIN,
}

sealed class ActivationEnvelopeVerificationResult {
    data class Valid(val envelope: ActivationEnvelope) : ActivationEnvelopeVerificationResult()

    /** [kind] is the typed category a caller branches on; [reason] is human-readable diagnostic detail only, never parsed elsewhere. */
    data class Invalid(val kind: ActivationEnvelopeFailureKind, val reason: String) : ActivationEnvelopeVerificationResult()
}

/**
 * Verifies a [SignedActivationEnvelope] against activation-issuer trust
 * roots. Pure/no I/O: given the same inputs and [nowEpochMillis], always
 * the same result - see ActivationEnvelopeVerifierTest.
 *
 * Pipeline (matches the B56-1 task's specified order): strict decode of the
 * wire container -> schema/format validation -> issuer key lookup ->
 * canonicalize the unsigned envelope -> Ed25519 signature verification ->
 * time validation -> validated [ActivationEnvelope]. Fails closed at every
 * step - there is no partially-trusted result object.
 */
interface ActivationEnvelopeVerifier {
    fun verify(encoded: ByteArray, trustAnchors: ActivationIssuerTrustAnchors, nowEpochMillis: Long): ActivationEnvelopeVerificationResult
    fun verify(signed: SignedActivationEnvelope, trustAnchors: ActivationIssuerTrustAnchors, nowEpochMillis: Long): ActivationEnvelopeVerificationResult
}

/**
 * Real Ed25519 verification, reusing the exact same BouncyCastle
 * primitives as [Ed25519ManifestVerifier] (no second crypto stack
 * introduced).
 *
 * ## Clock policy (PR #92 correction)
 *
 * A single [clockSkewToleranceMillis] - defaulted to and normally equal to
 * [Ed25519ManifestVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS], not a second,
 * independently-invented tolerance - governs every clock-skew-tolerant
 * check here, exactly mirroring the existing manifest trust policy:
 *
 * 1. **`issuedAt` implausibly in the future** - `issuedAt > now + tolerance`
 *    -> `CLOCK_UNCERTAIN`. This is the SAME check
 *    [Ed25519ManifestVerifier.verify] makes for `EndpointManifest.issuedAtEpochMillis`,
 *    just reported under this verifier's own `CLOCK_UNCERTAIN` kind instead
 *    of manifest's `CLOCK_SKEW` (the B56-1 task requires `CLOCK_UNCERTAIN`
 *    to exist as its own kind here). A local clock running years ahead
 *    cannot be reliably distinguished from an envelope genuinely issued
 *    long ago by comparing `now` and `issuedAt` alone - this check exists to
 *    catch the ordinary "device clock is off by minutes" case, not to make
 *    any claim about detecting a maliciously/wildly wrong clock.
 * 2. **`notBefore` lower bound** - `now < notBefore - tolerance` ->
 *    `PACKAGE_NOT_YET_VALID`. Tolerance allows a device clock lagging the
 *    issuer's to still accept a freshly-issued envelope.
 * 3. **`expiresAt` upper bound** - `now >= expiresAt` -> `PACKAGE_EXPIRED`.
 *    Boundary-EXCLUSIVE and with NO added tolerance, matching
 *    [Ed25519ManifestVerifier]'s own `expiresAtEpochMillis <= nowEpochMillis`
 *    check exactly (same convention, restated as `now >= expiresAt`) -
 *    loosening this because "the device clock might be wrong" would blunt
 *    the one property `expiresAt` exists to guarantee.
 *
 * There is no separate "absurd clock" heuristic - a previous version of
 * this file had one (an arbitrary ~10-year `issuedAt` delta), which invented
 * a second, undocumented clock-trust model instead of reusing the existing
 * one; it has been removed.
 */
class Ed25519ActivationEnvelopeVerifier(
    private val clockSkewToleranceMillis: Long = Ed25519ManifestVerifier.DEFAULT_CLOCK_SKEW_TOLERANCE_MS,
) : ActivationEnvelopeVerifier {

    override fun verify(encoded: ByteArray, trustAnchors: ActivationIssuerTrustAnchors, nowEpochMillis: Long): ActivationEnvelopeVerificationResult {
        return when (val decoded = ActivationEnvelopeCodec.decode(encoded)) {
            is SignedActivationEnvelopeDecodeResult.Failure -> ActivationEnvelopeVerificationResult.Invalid(
                decoded.failure.toFailureKind(),
                "package decode failed: ${decoded.failure::class.simpleName}",
            )
            is SignedActivationEnvelopeDecodeResult.Success -> verify(decoded.signed, trustAnchors, nowEpochMillis)
        }
    }

    override fun verify(signed: SignedActivationEnvelope, trustAnchors: ActivationIssuerTrustAnchors, nowEpochMillis: Long): ActivationEnvelopeVerificationResult {
        val envelope = signed.envelope

        val publicKeyBytes = trustAnchors.publicKeyFor(envelope.issuerKeyId)
            ?: return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.ISSUER_KEY_UNKNOWN, "unknown issuer key id: ${envelope.issuerKeyId.value}")

        val canonical = ActivationEnvelopeCanonicalizer.canonicalBytes(envelope)
        val signatureValid = try {
            verifyEd25519(publicKeyBytes, canonical, signed.signature)
        } catch (e: IllegalArgumentException) {
            false
        }
        if (!signatureValid) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.PACKAGE_SIGNATURE_INVALID, "signature verification failed")
        }

        if (envelope.issuedAtEpochMillis > nowEpochMillis + clockSkewToleranceMillis) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.CLOCK_UNCERTAIN, "issuedAt is implausibly in the future")
        }
        if (nowEpochMillis < envelope.notBeforeEpochMillis - clockSkewToleranceMillis) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.PACKAGE_NOT_YET_VALID, "envelope is not yet valid")
        }
        if (nowEpochMillis >= envelope.expiresAtEpochMillis) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.PACKAGE_EXPIRED, "envelope has expired")
        }

        return ActivationEnvelopeVerificationResult.Valid(envelope)
    }

    private fun verifyEd25519(publicKeyBytes: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        require(publicKeyBytes.size == Ed25519PublicKeyParameters.KEY_SIZE) { "invalid Ed25519 public key length: ${publicKeyBytes.size}" }
        require(signature.size == SignedActivationEnvelope.SIGNATURE_LENGTH) { "invalid Ed25519 signature length: ${signature.size}" }
        val verifier = Ed25519Signer()
        verifier.init(false, Ed25519PublicKeyParameters(publicKeyBytes, 0))
        verifier.update(message, 0, message.size)
        return verifier.verifySignature(signature)
    }
}
