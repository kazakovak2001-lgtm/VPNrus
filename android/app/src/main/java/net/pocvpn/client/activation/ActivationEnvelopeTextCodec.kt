package net.pocvpn.client.activation

import java.util.Base64

/**
 * B56-1 - user-transfer-safe textual form of an [ActivationEnvelopeCodec]
 * container: URL-safe base64, no padding, matching the repository's
 * existing `java.util.Base64` convention (no dedicated wrapper class exists
 * elsewhere in this codebase - see EmbeddedBootstrapManifest/Shadowsocks2022Credential).
 * Deterministic and whitespace-independent; the decoder is strict (rejects
 * anything that isn't valid URL-safe base64 WITHOUT padding) and never
 * throws - malformed text maps to the same typed
 * [ActivationEnvelopeParseFailure.TruncatedOrMalformed] failure as any
 * other malformed container.
 *
 * ## Pre-decode size bound (PR #92 correction)
 *
 * [text]'s length is checked against [MAX_TEXT_LENGTH] BEFORE any Base64
 * decoding is attempted. Without this, `Base64.getUrlDecoder().decode(text)`
 * would allocate a byte array proportional to an attacker-controlled input
 * string's length before [ActivationEnvelopeCodec.decode] ever gets a
 * chance to enforce [ActivationEnvelopeCodec.MAX_ENCODED_BYTES] - a very
 * large pasted/imported string could force a large allocation ahead of any
 * binary-level size check. [MAX_TEXT_LENGTH] is derived from
 * [ActivationEnvelopeCodec.MAX_ENCODED_BYTES] (not a second, independently
 * chosen magic number), rounded UP to the padded-base64 length formula
 * (`ceil(n/3)*4`), so it is always at least as large as the longest string
 * that could ever legitimately decode to a package within the binary limit.
 *
 * ## Canonical strictness
 *
 * [CANONICAL_ALPHABET] rejects anything outside `[A-Za-z0-9_-]` BEFORE
 * decoding - this alone rejects standard-alphabet `+`/`/`, `=` padding, and
 * whitespace, since the canonical encoding form ([encode]) never emits any
 * of those.
 *
 * Out of scope for B56-1, deferred to B56-7: QR generation/scanning,
 * Android deep-link handling, clipboard UI, file import UI. This object
 * only turns bytes into a safe-to-paste/QR-encode string and back - nothing
 * about how that string reaches the device.
 */
object ActivationEnvelopeTextCodec {
    private val ENCODER = Base64.getUrlEncoder().withoutPadding()
    private val DECODER = Base64.getUrlDecoder()
    private val CANONICAL_ALPHABET = Regex("^[A-Za-z0-9_-]+$")

    /** See class docs on the pre-decode size bound. */
    val MAX_TEXT_LENGTH: Int = ((ActivationEnvelopeCodec.MAX_ENCODED_BYTES + 2) / 3) * 4

    fun encode(signed: SignedActivationEnvelope): String =
        ENCODER.encodeToString(ActivationEnvelopeCodec.encode(signed))

    fun decode(text: String): SignedActivationEnvelopeDecodeResult {
        if (text.length > MAX_TEXT_LENGTH) {
            return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.EncodedPackageTooLarge)
        }
        if (text.isEmpty() || !CANONICAL_ALPHABET.matches(text)) {
            return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        }
        val bytes = try {
            DECODER.decode(text)
        } catch (e: IllegalArgumentException) {
            return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        }
        return ActivationEnvelopeCodec.decode(bytes)
    }
}
