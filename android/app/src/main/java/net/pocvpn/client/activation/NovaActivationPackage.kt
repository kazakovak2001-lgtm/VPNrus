package net.pocvpn.client.activation

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.Base64

/**
 * B56-5 - the `NovaActivationPackage` container from
 * docs/RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md section 5/7: a
 * TRANSPORT wrapper around two independently authenticated objects, never
 * a third trust root and never itself signed.
 *
 * - [signedEnvelope] - the existing B56-1 [SignedActivationEnvelope]
 *   (activation-issuer key, entitlement only).
 * - [bootstrapBundle] - OPTIONAL exact `SignedManifestCodec` bytes of a
 *   `SignedBootstrapBundle` (existing manifest key, network facts only).
 *   Kept as the exact wire bytes, not a decoded object, because the
 *   envelope's `bootstrapBundleRef.contentHash` binds the SHA-256 of exactly
 *   these bytes (see gateway/tools/activation_envelope_issuer.py
 *   `--bootstrap-bundle`).
 *
 * Level-2 extension point: V1 reserves a length-prefixed section for a
 * pre-issued bootstrap capability (architecture section 7 "Level-2-Capable
 * Recovery Package", slice B56-6). In V1 it MUST be empty - a non-empty
 * section is rejected as [ActivationPackageParseFailure.Level2NotSupported],
 * never silently ignored, so a recovery package is never mistaken for a
 * standard one. B56-6 defines its content; the layout already has room.
 *
 * Binary layout (all ints big-endian, no trailing bytes):
 * ```
 * int   domainTagLength, bytes DOMAIN_TAG ("NOVA_ACTIVATION_PACKAGE_V1", UTF-8)
 * int   schemaVersion (== 1)
 * int   envelopeLength (1..ActivationEnvelopeCodec.MAX_ENCODED_BYTES), bytes
 * int   bundleLength (0 = absent, else 1..MAX_BUNDLE_BYTES), bytes
 * int   level2SectionLength (MUST be 0 in V1)
 * ```
 * Text form (QR / deep link payload / clipboard / manual entry):
 * `nova-activation:1:` + unpadded canonical Base64URL of the bytes above.
 * The prefix is what distinguishes a package from a raw activation
 * credential (whose own alphabet is also URL-safe Base64) - it is a format
 * marker only, never a trust signal.
 */
class NovaActivationPackage(val signedEnvelope: SignedActivationEnvelope, bootstrapBundle: ByteArray?) {
    private val bundleBytes: ByteArray? = bootstrapBundle?.copyOf()

    val bootstrapBundle: ByteArray? get() = bundleBytes?.copyOf()

    init {
        bundleBytes?.let {
            require(it.isNotEmpty() && it.size <= MAX_BUNDLE_BYTES) { "bootstrap bundle length out of range: ${it.size}" }
        }
    }

    override fun toString(): String =
        "NovaActivationPackage(envelope=${signedEnvelope.envelope}, bootstrapBundle=${bundleBytes?.let { "<${it.size} bytes>" } ?: "null"})"

    companion object {
        const val DOMAIN_TAG = "NOVA_ACTIVATION_PACKAGE_V1"
        const val SCHEMA_VERSION = 1
        const val TEXT_PREFIX = "nova-activation:1:"
        const val MAX_BUNDLE_BYTES = 262_144
        const val MAX_ENCODED_BYTES = 16 + DOMAIN_TAG.length + ActivationEnvelopeCodec.MAX_ENCODED_BYTES + MAX_BUNDLE_BYTES + 8
    }
}

/**
 * Every import source (QR scan, deep link, file, clipboard, manual entry)
 * is reduced to one of these two shapes BEFORE any parsing - the source
 * itself confers no trust; only the signatures checked afterwards do.
 */
sealed class ActivationPackageInput {
    /** QR payload, deep-link parameter, clipboard, or manual entry. */
    class Text(val text: String) : ActivationPackageInput() {
        override fun toString(): String = "Text(<${text.length} chars REDACTED>)"
    }

    /** A package file's raw bytes. */
    class Bytes(bytes: ByteArray) : ActivationPackageInput() {
        private val raw = bytes.copyOf()
        val bytes: ByteArray get() = raw.copyOf()
        override fun toString(): String = "Bytes(<${raw.size} bytes REDACTED>)"
    }
}

sealed class ActivationPackageParseResult {
    class Success(val pkg: NovaActivationPackage) : ActivationPackageParseResult()
    data class Failure(val failure: ActivationPackageParseFailure) : ActivationPackageParseResult()
}

sealed class ActivationPackageParseFailure {
    object NotAPackage : ActivationPackageParseFailure()
    object Malformed : ActivationPackageParseFailure()
    object TooLarge : ActivationPackageParseFailure()
    data class UnsupportedSchemaVersion(val version: Int) : ActivationPackageParseFailure()
    object Level2NotSupported : ActivationPackageParseFailure()
    /** The embedded envelope failed the EXISTING [ActivationEnvelopeCodec.decode]. */
    data class EnvelopeMalformed(val failure: ActivationEnvelopeParseFailure) : ActivationPackageParseFailure()
}

/** Structural parsing only - no cryptography happens here (see [ActivationPackageImporter]). */
object ActivationPackageParser {
    private val ENCODER = Base64.getUrlEncoder().withoutPadding()
    private val DECODER = Base64.getUrlDecoder()
    private val CANONICAL_ALPHABET = Regex("^[A-Za-z0-9_-]+$")
    private val DOMAIN_TAG_BYTES = NovaActivationPackage.DOMAIN_TAG.toByteArray(Charsets.UTF_8)

    val MAX_TEXT_LENGTH: Int = NovaActivationPackage.TEXT_PREFIX.length + ((NovaActivationPackage.MAX_ENCODED_BYTES + 2) / 3) * 4

    /** Routing hint for UI entry fields: true only for the explicit package text prefix. */
    fun looksLikePackageText(text: String): Boolean = text.trim().startsWith(NovaActivationPackage.TEXT_PREFIX)

    fun parse(input: ActivationPackageInput): ActivationPackageParseResult = when (input) {
        is ActivationPackageInput.Text -> parseText(input.text)
        is ActivationPackageInput.Bytes -> decode(input.bytes)
    }

    private fun parseText(raw: String): ActivationPackageParseResult {
        if (raw.length > MAX_TEXT_LENGTH) return failure(ActivationPackageParseFailure.TooLarge)
        val text = raw.trim()
        if (!text.startsWith(NovaActivationPackage.TEXT_PREFIX)) return failure(ActivationPackageParseFailure.NotAPackage)
        val payload = text.substring(NovaActivationPackage.TEXT_PREFIX.length)
        if (payload.isEmpty() || !CANONICAL_ALPHABET.matches(payload)) return failure(ActivationPackageParseFailure.Malformed)
        val bytes = try {
            DECODER.decode(payload)
        } catch (e: IllegalArgumentException) {
            return failure(ActivationPackageParseFailure.Malformed)
        }
        // Reject non-canonical Base64 aliases (same rule as ActivationEnvelopeTextCodec).
        if (ENCODER.encodeToString(bytes) != payload) return failure(ActivationPackageParseFailure.Malformed)
        return decode(bytes)
    }

    fun encodeText(pkg: NovaActivationPackage): String = NovaActivationPackage.TEXT_PREFIX + ENCODER.encodeToString(encode(pkg))

    fun encode(pkg: NovaActivationPackage): ByteArray {
        val envelopeBytes = ActivationEnvelopeCodec.encode(pkg.signedEnvelope)
        val bundle = pkg.bootstrapBundle
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(DOMAIN_TAG_BYTES.size)
            d.write(DOMAIN_TAG_BYTES)
            d.writeInt(NovaActivationPackage.SCHEMA_VERSION)
            d.writeInt(envelopeBytes.size)
            d.write(envelopeBytes)
            d.writeInt(bundle?.size ?: 0)
            bundle?.let { d.write(it) }
            d.writeInt(0) // V1: reserved Level-2 section, always empty.
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): ActivationPackageParseResult {
        if (bytes.size > NovaActivationPackage.MAX_ENCODED_BYTES) return failure(ActivationPackageParseFailure.TooLarge)
        return try {
            val stream = bytes.inputStream()
            DataInputStream(stream).use { input ->
                val tagLen = input.readInt()
                if (tagLen != DOMAIN_TAG_BYTES.size) return failure(ActivationPackageParseFailure.Malformed)
                val tag = ByteArray(tagLen).also { input.readFully(it) }
                if (!tag.contentEquals(DOMAIN_TAG_BYTES)) return failure(ActivationPackageParseFailure.Malformed)

                val version = input.readInt()
                if (version != NovaActivationPackage.SCHEMA_VERSION) {
                    return failure(ActivationPackageParseFailure.UnsupportedSchemaVersion(version))
                }

                val envelopeLen = input.readInt()
                if (envelopeLen !in 1..ActivationEnvelopeCodec.MAX_ENCODED_BYTES) return failure(ActivationPackageParseFailure.Malformed)
                val envelopeBytes = ByteArray(envelopeLen).also { input.readFully(it) }

                val bundleLen = input.readInt()
                if (bundleLen !in 0..NovaActivationPackage.MAX_BUNDLE_BYTES) return failure(ActivationPackageParseFailure.Malformed)
                val bundle = if (bundleLen == 0) null else ByteArray(bundleLen).also { input.readFully(it) }

                val level2Len = input.readInt()
                if (level2Len < 0) return failure(ActivationPackageParseFailure.Malformed)
                if (level2Len != 0) return failure(ActivationPackageParseFailure.Level2NotSupported)

                if (stream.available() != 0) return failure(ActivationPackageParseFailure.Malformed)

                when (val decoded = ActivationEnvelopeCodec.decode(envelopeBytes)) {
                    is SignedActivationEnvelopeDecodeResult.Failure ->
                        failure(ActivationPackageParseFailure.EnvelopeMalformed(decoded.failure))
                    is SignedActivationEnvelopeDecodeResult.Success ->
                        ActivationPackageParseResult.Success(NovaActivationPackage(decoded.signed, bundle))
                }
            }
        } catch (e: java.io.IOException) {
            failure(ActivationPackageParseFailure.Malformed)
        } catch (e: IllegalArgumentException) {
            failure(ActivationPackageParseFailure.Malformed)
        }
    }

    private fun failure(f: ActivationPackageParseFailure) = ActivationPackageParseResult.Failure(f)
}
