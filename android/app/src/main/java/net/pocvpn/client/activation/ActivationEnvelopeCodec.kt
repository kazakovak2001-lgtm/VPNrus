package net.pocvpn.client.activation

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * B56-1 - the ONE binary container format for a [SignedActivationEnvelope]
 * on the wire or in an imported package: `[formatVersion:Int]
 * [canonicalLen:Int][canonicalBytes][signatureLen:Int][signature]`. Exactly
 * mirrors [net.pocvpn.client.reachability.SignedManifestCodec]'s shape and
 * reasoning (one container format, never two independently-drifting
 * parsers for the same logical artifact) - the only difference is this
 * decode path returns a typed [ActivationEnvelopeDecodeResult] instead of
 * throwing, since this container is the entry point for
 * attacker-controlled imported data (see the B56-1 task's PARSER
 * STRICTNESS / SIZE LIMITS requirements) and callers need a closed typed
 * failure model rather than an uncaught exception.
 *
 * This container's own `FORMAT_VERSION` is the wire-format version for the
 * ENVELOPE specifically - see [ActivationEnvelope]'s companion docs for why
 * this is a different concept than the future `NovaActivationPackage`
 * container's business-level `schemaVersion` field (B56-1 does not
 * implement that container).
 */
object ActivationEnvelopeCodec {
    private const val FORMAT_VERSION = 1

    /**
     * Conservative upper bound on the entire encoded package this parser
     * will ever attempt to read - rejects a huge declared length before
     * allocating. Public (not `private`) so [ActivationEnvelopeTextCodec]
     * can derive its own pre-Base64-decode text-length bound from the SAME
     * constant (PR #92's text-transport size-bound correction) instead of
     * duplicating a magic number that could drift out of sync.
     */
    const val MAX_ENCODED_BYTES = 32_768

    fun encode(signed: SignedActivationEnvelope): ByteArray {
        val canonicalBytes = ActivationEnvelopeCanonicalizer.canonicalBytes(signed.envelope)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(FORMAT_VERSION)
            d.writeInt(canonicalBytes.size)
            d.write(canonicalBytes)
            d.writeInt(signed.signature.size)
            d.write(signed.signature)
        }
        val bytes = out.toByteArray()
        // PR #92 blocker 5: never emit what our own decode() would reject.
        check(bytes.size <= MAX_ENCODED_BYTES) { "encoded activation package exceeds MAX_ENCODED_BYTES ($MAX_ENCODED_BYTES): ${bytes.size}" }
        return bytes
    }

    /**
     * Strict decode: requires exact container consumption (any trailing
     * byte, however small, is rejected - same discipline as
     * SignedManifestCodec.decode) and never throws for malformed/truncated/
     * oversized input - always a typed [SignedActivationEnvelopeDecodeResult].
     */
    fun decode(bytes: ByteArray): SignedActivationEnvelopeDecodeResult {
        if (bytes.size > MAX_ENCODED_BYTES) {
            return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.EncodedPackageTooLarge)
        }
        return try {
            val stream = bytes.inputStream()
            DataInputStream(stream).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) {
                    return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.UnsupportedFormatVersion(version))
                }
                val canonicalLen = input.readInt()
                if (canonicalLen < 0 || canonicalLen > ActivationEnvelopeCanonicalizer.MAX_CANONICAL_BYTES) {
                    return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
                }
                val canonicalBytes = ByteArray(canonicalLen)
                input.readFully(canonicalBytes)

                val sigLen = input.readInt()
                if (sigLen != SignedActivationEnvelope.SIGNATURE_LENGTH) {
                    return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidSignatureLength)
                }
                val signature = ByteArray(sigLen)
                input.readFully(signature)

                if (stream.available() != 0) {
                    return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TrailingBytes)
                }

                when (val decoded = ActivationEnvelopeCanonicalizer.decode(canonicalBytes)) {
                    is ActivationEnvelopeDecodeResult.Failure -> SignedActivationEnvelopeDecodeResult.Failure(decoded.failure)
                    is ActivationEnvelopeDecodeResult.Success -> SignedActivationEnvelopeDecodeResult.Success(
                        SignedActivationEnvelope(decoded.envelope, signature),
                    )
                }
            }
        } catch (e: java.io.EOFException) {
            SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: java.io.IOException) {
            SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: IllegalArgumentException) {
            SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: OutOfMemoryError) {
            SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        }
    }
}

/** Result of [ActivationEnvelopeCodec.decode] - never throws for malformed input. */
sealed class SignedActivationEnvelopeDecodeResult {
    data class Success(val signed: SignedActivationEnvelope) : SignedActivationEnvelopeDecodeResult()
    data class Failure(val failure: ActivationEnvelopeParseFailure) : SignedActivationEnvelopeDecodeResult()
}
