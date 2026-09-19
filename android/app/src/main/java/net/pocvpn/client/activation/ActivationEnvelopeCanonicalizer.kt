package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Deterministic, dependency-free binary encoding of an [ActivationEnvelope] -
 * the exact bytes an activation-issuer signs and a client verifies against.
 * Mirrors [net.pocvpn.client.reachability.ManifestCanonicalizer]'s design
 * discipline exactly (fixed field order, explicit widths, length-prefixed
 * strings/lists, no JSON/serialization-framework dependence) for the same
 * reasons - one fewer external spec to get exactly right on a
 * signature-critical path.
 *
 * ## Domain separation
 *
 * The FIRST field written is a fixed [DOMAIN_TAG] string, unique to this
 * object type. Both this envelope and [net.pocvpn.client.reachability.EndpointManifest]
 * use Ed25519 signatures, and although activation-issuer keys and manifest
 * keys are required to be disjoint sets (see [FixedActivationIssuerTrustAnchors]),
 * the domain tag makes the two canonical byte streams incompatible by
 * construction: a signature valid over one object's canonical bytes cannot
 * become "accidentally valid" over the other's, even under an operational
 * mistake that reused the same key material for both roles.
 *
 * Unlike [net.pocvpn.client.reachability.ManifestCanonicalizer], which sorts
 * its endpoint list before encoding (manifest endpoint SET has no
 * meaningful order), [bootstrapEndpointHints] here is a ranking hint whose
 * ORDER is itself part of the signed data - it is encoded and decoded
 * exactly as given, never sorted.
 */
object ActivationEnvelopeCanonicalizer {
    /** Domain/type marker - see class docs. Never reused for another signed object type. */
    const val DOMAIN_TAG = "NOVA_ACTIVATION_ENVELOPE_V1"

    /** This canonical field-schema's own version - see [ActivationEnvelopeCodec] for the outer wire-container version, which is a separate concept (see this file's [ActivationEnvelope] companion docs on the schema-version boundary). */
    const val FORMAT_VERSION = 1

    fun canonicalBytes(envelope: ActivationEnvelope): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            writeString(d, DOMAIN_TAG)
            d.writeInt(FORMAT_VERSION)
            writeString(d, envelope.activationId.value)
            writeString(d, envelope.credential.value)
            d.writeLong(envelope.issuedAtEpochMillis)
            d.writeLong(envelope.notBeforeEpochMillis)
            d.writeLong(envelope.expiresAtEpochMillis)
            val bundleRef = envelope.bootstrapBundleRef
            d.writeBoolean(bundleRef != null)
            if (bundleRef != null) {
                d.writeInt(bundleRef.manifestVersion)
                writeBytes(d, bundleRef.contentHash)
            }
            d.writeInt(envelope.bootstrapEndpointHints.size)
            envelope.bootstrapEndpointHints.forEach { writeString(d, it.value) }
            val capabilityHint = envelope.bootstrapCapabilityHint
            d.writeBoolean(capabilityHint != null)
            if (capabilityHint != null) {
                writeBytes(d, capabilityHint)
            }
            writeBytes(d, envelope.nonce)
            writeString(d, envelope.issuerKeyId.value)
        }
        return out.toByteArray()
    }

    /**
     * Strict decode of canonical bytes back into an [ActivationEnvelope].
     * Returns a typed [ActivationEnvelopeParseFailure] rather than throwing
     * for any malformed/attacker-controlled input - see
     * [ActivationEnvelopeCodec], the caller that owns the outer container
     * format and turns these into architecture-level failures.
     */
    fun decode(bytes: ByteArray): ActivationEnvelopeDecodeResult {
        return try {
            val stream = bytes.inputStream()
            DataInputStream(stream).use { d ->
                val domainTag = readString(d, MAX_DOMAIN_TAG_BYTES) ?: return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
                if (domainTag != DOMAIN_TAG) return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.WrongDomainTag)

                val formatVersion = d.readInt()
                if (formatVersion != FORMAT_VERSION) return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.UnsupportedFormatVersion(formatVersion))

                val activationIdRaw = readString(d, ActivationId.MAX_LENGTH) ?: return malformed()
                val activationId = runCatching { ActivationId(activationIdRaw) }.getOrElse {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidActivationId)
                }

                val credentialRaw = readString(d, ActivationCredential.MAX_LENGTH) ?: return malformed()
                val credential = runCatching { ActivationCredential(credentialRaw) }.getOrElse {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidCredential)
                }

                val issuedAt = d.readLong()
                val notBefore = d.readLong()
                val expiresAt = d.readLong()

                val hasBundleRef = d.readBoolean()
                val bundleRef = if (hasBundleRef) {
                    val manifestVersion = d.readInt()
                    val contentHash = readBytes(d, ActivationBundleRef.CONTENT_HASH_LENGTH) ?: return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidBundleRefHashLength)
                    if (contentHash.size != ActivationBundleRef.CONTENT_HASH_LENGTH) {
                        return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidBundleRefHashLength)
                    }
                    val ref = runCatching { ActivationBundleRef(manifestVersion, contentHash) }.getOrElse {
                        return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidBundleRefManifestVersion)
                    }
                    ref
                } else null

                val hintCount = d.readInt()
                if (hintCount < 0 || hintCount > ActivationEnvelope.MAX_ENDPOINT_HINTS) {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TooManyEndpointHints)
                }
                val hints = ArrayList<EndpointId>(hintCount)
                repeat(hintCount) {
                    val raw = readString(d, MAX_ENDPOINT_ID_BYTES) ?: return malformed()
                    val id = runCatching { EndpointId(raw) }.getOrElse {
                        return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidEndpointHint)
                    }
                    hints.add(id)
                }
                if (hints.toSet().size != hints.size) {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.DuplicateEndpointHint)
                }

                val hasCapabilityHint = d.readBoolean()
                val capabilityHint = if (hasCapabilityHint) {
                    readBytes(d, ActivationEnvelope.MAX_CAPABILITY_HINT_BYTES, allowShorter = true)
                        ?: return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.CapabilityHintTooLarge)
                } else null

                val nonce = readBytes(d, ActivationEnvelope.NONCE_LENGTH)
                if (nonce == null || nonce.size != ActivationEnvelope.NONCE_LENGTH) {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidNonceLength)
                }

                val issuerKeyIdRaw = readString(d, ActivationIssuerKeyId.MAX_LENGTH) ?: return malformed()
                val issuerKeyId = runCatching { ActivationIssuerKeyId(issuerKeyIdRaw) }.getOrElse {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidIssuerKeyId)
                }

                if (stream.available() != 0) {
                    return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TrailingBytes)
                }

                val envelope = runCatching {
                    ActivationEnvelope(
                        activationId = activationId,
                        credential = credential,
                        issuedAtEpochMillis = issuedAt,
                        notBeforeEpochMillis = notBefore,
                        expiresAtEpochMillis = expiresAt,
                        bootstrapBundleRef = bundleRef,
                        bootstrapEndpointHints = hints,
                        bootstrapCapabilityHint = capabilityHint,
                        nonce = nonce,
                        issuerKeyId = issuerKeyId,
                    )
                }.getOrElse { return ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.InvalidTimestampOrdering) }

                ActivationEnvelopeDecodeResult.Success(envelope)
            }
        } catch (e: java.io.EOFException) {
            ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: java.io.IOException) {
            ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: IllegalArgumentException) {
            ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        } catch (e: OutOfMemoryError) {
            ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)
        }
    }

    private fun malformed() = ActivationEnvelopeDecodeResult.Failure(ActivationEnvelopeParseFailure.TruncatedOrMalformed)

    private fun writeString(d: DataOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_STRING_BYTES) { "string field too long: ${bytes.size} bytes" }
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    /** Returns null (never throws) on any length/EOF problem, so the caller can map it to a typed decode failure. */
    private fun readString(d: DataInputStream, maxBytes: Int): String? {
        val len = try { d.readInt() } catch (e: java.io.EOFException) { return null }
        if (len < 0 || len > maxBytes) return null
        val bytes = ByteArray(len)
        return try {
            d.readFully(bytes)
            String(bytes, Charsets.UTF_8)
        } catch (e: java.io.EOFException) {
            null
        }
    }

    private fun writeBytes(d: DataOutputStream, bytes: ByteArray) {
        require(bytes.size <= MAX_STRING_BYTES) { "byte field too long: ${bytes.size} bytes" }
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    /**
     * Reads a length-prefixed byte field. If [allowShorter] is false, the
     * declared length must equal [expectedOrMaxLength] exactly (used for
     * fixed-size fields like nonce/content-hash); if true,
     * [expectedOrMaxLength] is only an upper bound (used for
     * bootstrapCapabilityHint, which is variable-length up to a cap).
     * Returns null on any length/EOF problem.
     */
    private fun readBytes(d: DataInputStream, expectedOrMaxLength: Int, allowShorter: Boolean = false): ByteArray? {
        val len = try { d.readInt() } catch (e: java.io.EOFException) { return null }
        if (len < 0) return null
        if (allowShorter) {
            if (len > expectedOrMaxLength) return null
        } else {
            if (len != expectedOrMaxLength) return null
        }
        val bytes = ByteArray(len)
        return try {
            d.readFully(bytes)
            bytes
        } catch (e: java.io.EOFException) {
            null
        }
    }

    private const val MAX_STRING_BYTES = 4096
    private const val MAX_DOMAIN_TAG_BYTES = 64
    private const val MAX_ENDPOINT_ID_BYTES = 128
}

/** Result of [ActivationEnvelopeCanonicalizer.decode] - never throws for malformed input. */
sealed class ActivationEnvelopeDecodeResult {
    data class Success(val envelope: ActivationEnvelope) : ActivationEnvelopeDecodeResult()
    data class Failure(val failure: ActivationEnvelopeParseFailure) : ActivationEnvelopeDecodeResult()
}

/**
 * Internal parser-detail failure model - CLOSED (sealed), never thrown as an
 * exception to callers. [ActivationEnvelopeVerifier] maps every case here
 * down to the small architecture-level [ActivationEnvelopeFailureKind] set;
 * this finer-grained type exists only for tests/diagnostics, never
 * exposed directly to end-user UX (see class docs on
 * [ActivationEnvelopeFailureKind]).
 */
sealed class ActivationEnvelopeParseFailure {
    object TruncatedOrMalformed : ActivationEnvelopeParseFailure()
    data class UnsupportedFormatVersion(val version: Int) : ActivationEnvelopeParseFailure()
    object WrongDomainTag : ActivationEnvelopeParseFailure()
    object InvalidActivationId : ActivationEnvelopeParseFailure()
    object InvalidCredential : ActivationEnvelopeParseFailure()
    object InvalidTimestampOrdering : ActivationEnvelopeParseFailure()
    object InvalidBundleRefHashLength : ActivationEnvelopeParseFailure()
    object InvalidBundleRefManifestVersion : ActivationEnvelopeParseFailure()
    object TooManyEndpointHints : ActivationEnvelopeParseFailure()
    object InvalidEndpointHint : ActivationEnvelopeParseFailure()
    object DuplicateEndpointHint : ActivationEnvelopeParseFailure()
    object CapabilityHintTooLarge : ActivationEnvelopeParseFailure()
    object InvalidNonceLength : ActivationEnvelopeParseFailure()
    object InvalidIssuerKeyId : ActivationEnvelopeParseFailure()
    object InvalidSignatureLength : ActivationEnvelopeParseFailure()
    object TrailingBytes : ActivationEnvelopeParseFailure()
    object EncodedPackageTooLarge : ActivationEnvelopeParseFailure()

    /** Maps to the small closed set a verifier caller actually branches on - see [ActivationEnvelopeFailureKind]. */
    fun toFailureKind(): ActivationEnvelopeFailureKind = when (this) {
        is UnsupportedFormatVersion -> ActivationEnvelopeFailureKind.PACKAGE_VERSION_UNSUPPORTED
        else -> ActivationEnvelopeFailureKind.PACKAGE_MALFORMED
    }
}
