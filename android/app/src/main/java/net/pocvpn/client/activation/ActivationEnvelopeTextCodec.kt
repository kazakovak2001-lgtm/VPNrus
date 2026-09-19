package net.pocvpn.client.activation

import java.util.Base64

/**
 * B56-1 - user-transfer-safe textual form of an [ActivationEnvelopeCodec]
 * container: URL-safe base64, no padding, matching the repository's
 * existing `java.util.Base64` convention (no dedicated wrapper class exists
 * elsewhere in this codebase - see EmbeddedBootstrapManifest/Shadowsocks2022Credential).
 * Deterministic and whitespace-independent; the decoder is strict (rejects
 * anything that isn't valid URL-safe base64) and never throws - malformed
 * text maps to the same typed [ActivationEnvelopeParseFailure.TruncatedOrMalformed]
 * failure as any other malformed container.
 *
 * Out of scope for B56-1, deferred to B56-7: QR generation/scanning,
 * Android deep-link handling, clipboard UI, file import UI. This object
 * only turns bytes into a safe-to-paste/QR-encode string and back - nothing
 * about how that string reaches the device.
 */
object ActivationEnvelopeTextCodec {
    private val ENCODER = Base64.getUrlEncoder().withoutPadding()
    private val DECODER = Base64.getUrlDecoder()

    fun encode(signed: SignedActivationEnvelope): String =
        ENCODER.encodeToString(ActivationEnvelopeCodec.encode(signed))

    fun decode(text: String): SignedActivationEnvelopeDecodeResult {
        val bytes = try {
            DECODER.decode(text)
        } catch (e: IllegalArgumentException) {
            return SignedActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        }
        return ActivationEnvelopeCodec.decode(bytes)
    }
}
