package net.pocvpn.client.activation

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
 * primitives as [net.pocvpn.client.reachability.Ed25519ManifestVerifier]
 * (no second crypto stack introduced).
 *
 * [clockSkewToleranceMillis] applies ONLY to the [ActivationEnvelope.notBeforeEpochMillis]
 * lower bound (a device clock that lags the issuer's may otherwise see a
 * freshly-issued envelope as "not yet valid"). Expiry
 * ([ActivationEnvelope.expiresAtEpochMillis]) is checked strictly, with no
 * tolerance added - loosening it because "the device clock might be wrong"
 * would blunt the one property `expiresAt` exists to guarantee.
 * [absurdClockSkewToleranceMillis] guards the opposite extreme: a device
 * clock so far from the envelope's own timestamps that treating the result
 * as an ordinary not-yet-valid/expired verdict would be misleading -
 * that case is reported as `CLOCK_UNCERTAIN` instead.
 */
class Ed25519ActivationEnvelopeVerifier(
    private val clockSkewToleranceMillis: Long = DEFAULT_CLOCK_SKEW_TOLERANCE_MS,
    private val absurdClockSkewToleranceMillis: Long = DEFAULT_ABSURD_CLOCK_SKEW_TOLERANCE_MS,
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

        if (kotlin.math.abs(nowEpochMillis - envelope.issuedAtEpochMillis) > absurdClockSkewToleranceMillis) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.CLOCK_UNCERTAIN, "device clock implausibly far from envelope issuedAt")
        }
        if (nowEpochMillis < envelope.notBeforeEpochMillis - clockSkewToleranceMillis) {
            return ActivationEnvelopeVerificationResult.Invalid(ActivationEnvelopeFailureKind.PACKAGE_NOT_YET_VALID, "envelope is not yet valid")
        }
        if (nowEpochMillis > envelope.expiresAtEpochMillis) {
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

    companion object {
        const val DEFAULT_CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000L
        /** A device clock more than ~10 years from the envelope's own issuedAt is treated as unreliable rather than a legitimate not-yet-valid/expired verdict. */
        const val DEFAULT_ABSURD_CLOCK_SKEW_TOLERANCE_MS = 10L * 365 * 24 * 60 * 60 * 1000
    }
}
