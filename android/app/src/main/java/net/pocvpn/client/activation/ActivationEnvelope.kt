package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointId

/**
 * B56-1 - the activation authority's signed data model. See
 * docs/RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md section 6/7 for the
 * approved design; this file implements ONLY the [ActivationEnvelope]
 * schema (the object signed by a future delegated activation-issuer key).
 *
 * This is deliberately a SEPARATE authority from the existing
 * SignedManifest/EndpointManifest (network authority, signed by the
 * existing manifest signing key - see net.pocvpn.client.reachability).
 * An [ActivationEnvelope] MUST NEVER carry a host/IP/port/SNI/gateway/
 * transport/URL fact - see [ActivationEnvelope]'s own field docs and
 * ActivationEnvelopeCanonicalizerTest for why every field here is either
 * activation entitlement metadata or a non-authoritative hint over
 * endpoints the client ALREADY trusts via a separately-verified manifest.
 *
 * B56-1 does NOT implement: SignedBootstrapBundle, NovaActivationPackage
 * (the outer container - see [SCHEMA_VERSIONING boundary] below), network
 * I/O, QR/UI, or server-side issuance. Those are later B56 slices.
 *
 * ## Schema-version boundary (design choice for B56-1)
 *
 * The architecture doc places `schemaVersion` on the outer
 * `NovaActivationPackage` container (section 7), which this slice does not
 * implement. This file therefore takes approach "B" from the B56-1 task:
 * [ActivationEnvelope]/[ActivationEnvelopeCanonicalizer] is an
 * envelope-payload format only. It owns its OWN wire-format version
 * ([ActivationEnvelopeCodec]'s `FORMAT_VERSION`, exactly analogous to
 * [net.pocvpn.client.reachability.SignedManifestCodec]'s constant of the
 * same name) so the encoded envelope bytes are self-describing and can
 * reject an unsupported wire format on their own
 * (`PACKAGE_VERSION_UNSUPPORTED`). The BUSINESS `schemaVersion` field of
 * the future `NovaActivationPackage` container is out of scope here - a
 * later slice reads it and decides whether to even hand the inner envelope
 * bytes to this parser. No architecture field has been silently moved:
 * `schemaVersion` still belongs to the container, not to this envelope.
 */
data class ActivationId(val value: String) {
    init {
        require(FORMAT.matches(value)) { "activationId must be 32 lowercase hex characters" }
    }

    companion object {
        /** Matches gateway/api/activations.py's `_ACTIVATION_ID_RE` exactly - never a second ID format. */
        private val FORMAT = Regex("^[0-9a-f]{32}$")
        const val MAX_LENGTH = 32
    }
}

/**
 * The existing activation bearer credential (gateway/tools/activation_tokens.py
 * `issue_activation` -> `secrets.token_urlsafe(32)`, i.e. URL-safe base64
 * without padding). Sensitive: never logged, never in `toString()`/
 * exception messages - [toString] is overridden to redact; equals/hashCode
 * stay value-based (needed for round-trip/mutation tests) but callers must
 * not print them either.
 */
class ActivationCredential(val value: String) {
    init {
        require(value.isNotEmpty()) { "credential must not be empty" }
        require(value.length <= MAX_LENGTH) { "credential exceeds max length ($MAX_LENGTH): ${value.length}" }
        require(FORMAT.matches(value)) { "credential must be URL-safe base64 (no padding), matching secrets.token_urlsafe output" }
    }

    override fun equals(other: Any?): Boolean = other is ActivationCredential && value == other.value
    override fun hashCode(): Int = value.hashCode()
    override fun toString(): String = "ActivationCredential(REDACTED)"

    companion object {
        private val FORMAT = Regex("^[A-Za-z0-9_-]+$")
        /** Generous headroom over today's 43-char token_urlsafe(32) output for future rotation. */
        const val MAX_LENGTH = 256
    }
}

/** Identifies which activation-issuer public key must verify an [ActivationEnvelope]. Never a manifest signing-key id - see [ActivationIssuerKeyId]. */
data class ActivationIssuerKeyId(val value: String) {
    init {
        require(value.isNotBlank()) { "issuerKeyId must not be blank" }
        require(value.length <= MAX_LENGTH) { "issuerKeyId exceeds max length ($MAX_LENGTH): ${value.length}" }
    }

    companion object {
        const val MAX_LENGTH = 64
    }
}

/**
 * Informational cross-reference to a separately-signed SignedBootstrapBundle
 * (not implemented in B56-1). NEVER carries a host/port/network fact - only
 * a manifest version number and a content hash that a client can use to
 * confirm "this is the bundle the envelope was issued alongside", nothing
 * more.
 */
class ActivationBundleRef(val manifestVersion: Int, val contentHash: ByteArray) {
    init {
        require(manifestVersion >= 1) { "manifestVersion must be >= 1: $manifestVersion" }
        require(contentHash.size == CONTENT_HASH_LENGTH) { "contentHash must be exactly $CONTENT_HASH_LENGTH bytes (SHA-256): ${contentHash.size}" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ActivationBundleRef) return false
        return manifestVersion == other.manifestVersion && contentHash.contentEquals(other.contentHash)
    }

    override fun hashCode(): Int = 31 * manifestVersion + contentHash.contentHashCode()
    override fun toString(): String = "ActivationBundleRef(manifestVersion=$manifestVersion, contentHash=<${contentHash.size} bytes>)"

    companion object {
        /** Fixed hash format: SHA-256. */
        const val CONTENT_HASH_LENGTH = 32
    }
}

/**
 * The activation authority's signed payload. Every field listed here is
 * covered by [signature] via [ActivationEnvelopeCanonicalizer] - see
 * ActivationEnvelopeMutationTest for proof that mutating any one of them
 * invalidates the signature.
 *
 * [bootstrapEndpointHints] and [bootstrapCapabilityHint] are NON-authoritative:
 * they may only reorder/accelerate use of endpoints the client already
 * trusts via a separately-verified manifest, and this layer does not
 * interpret [bootstrapCapabilityHint] at all (bytes are preserved exactly,
 * size-bounded, and treated as sensitive).
 */
data class ActivationEnvelope(
    val activationId: ActivationId,
    val credential: ActivationCredential,
    val issuedAtEpochMillis: Long,
    val notBeforeEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val bootstrapBundleRef: ActivationBundleRef?,
    val bootstrapEndpointHints: List<EndpointId>,
    val bootstrapCapabilityHint: ByteArray?,
    val nonce: ByteArray,
    val issuerKeyId: ActivationIssuerKeyId,
) {
    init {
        require(notBeforeEpochMillis < expiresAtEpochMillis) {
            "notBeforeEpochMillis ($notBeforeEpochMillis) must be before expiresAtEpochMillis ($expiresAtEpochMillis)"
        }
        require(nonce.size == NONCE_LENGTH) { "nonce must be exactly $NONCE_LENGTH bytes: ${nonce.size}" }
        require(bootstrapEndpointHints.size <= MAX_ENDPOINT_HINTS) {
            "too many bootstrapEndpointHints (${bootstrapEndpointHints.size} > $MAX_ENDPOINT_HINTS)"
        }
        val distinctHints = bootstrapEndpointHints.toSet()
        require(distinctHints.size == bootstrapEndpointHints.size) { "bootstrapEndpointHints contains a duplicate EndpointId" }
        bootstrapCapabilityHint?.let {
            require(it.size <= MAX_CAPABILITY_HINT_BYTES) { "bootstrapCapabilityHint exceeds max length ($MAX_CAPABILITY_HINT_BYTES): ${it.size}" }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ActivationEnvelope) return false
        return activationId == other.activationId &&
            credential == other.credential &&
            issuedAtEpochMillis == other.issuedAtEpochMillis &&
            notBeforeEpochMillis == other.notBeforeEpochMillis &&
            expiresAtEpochMillis == other.expiresAtEpochMillis &&
            bootstrapBundleRef == other.bootstrapBundleRef &&
            bootstrapEndpointHints == other.bootstrapEndpointHints &&
            (bootstrapCapabilityHint?.contentEquals(other.bootstrapCapabilityHint ?: ByteArray(0)) ?: (other.bootstrapCapabilityHint == null)) &&
            nonce.contentEquals(other.nonce) &&
            issuerKeyId == other.issuerKeyId
    }

    override fun hashCode(): Int {
        var result = activationId.hashCode()
        result = 31 * result + credential.hashCode()
        result = 31 * result + issuedAtEpochMillis.hashCode()
        result = 31 * result + notBeforeEpochMillis.hashCode()
        result = 31 * result + expiresAtEpochMillis.hashCode()
        result = 31 * result + (bootstrapBundleRef?.hashCode() ?: 0)
        result = 31 * result + bootstrapEndpointHints.hashCode()
        result = 31 * result + (bootstrapCapabilityHint?.contentHashCode() ?: 0)
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + issuerKeyId.hashCode()
        return result
    }

    /** Never prints [credential] or [bootstrapCapabilityHint] contents - both are sensitive. */
    override fun toString(): String =
        "ActivationEnvelope(activationId=$activationId, credential=REDACTED, issuedAtEpochMillis=$issuedAtEpochMillis, " +
            "notBeforeEpochMillis=$notBeforeEpochMillis, expiresAtEpochMillis=$expiresAtEpochMillis, " +
            "bootstrapBundleRef=$bootstrapBundleRef, bootstrapEndpointHints=$bootstrapEndpointHints, " +
            "bootstrapCapabilityHint=${if (bootstrapCapabilityHint != null) "<${bootstrapCapabilityHint.size} bytes REDACTED>" else "null"}, " +
            "nonce=<${nonce.size} bytes>, issuerKeyId=$issuerKeyId)"

    companion object {
        /** Architecture-approved size - see docs/RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md section 6. Local dedupe/import metadata only, NOT a replay-prevention security boundary. */
        const val NONCE_LENGTH = 16
        const val MAX_ENDPOINT_HINTS = 32
        const val MAX_CAPABILITY_HINT_BYTES = 4096
    }
}

/** An [ActivationEnvelope] plus the raw Ed25519 signature bytes over its canonical encoding - see [ActivationEnvelopeCanonicalizer]. */
data class SignedActivationEnvelope(val envelope: ActivationEnvelope, val signature: ByteArray) {
    init {
        require(signature.size == SIGNATURE_LENGTH) { "signature must be exactly $SIGNATURE_LENGTH bytes: ${signature.size}" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedActivationEnvelope) return false
        return envelope == other.envelope && signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int = 31 * envelope.hashCode() + signature.contentHashCode()

    companion object {
        const val SIGNATURE_LENGTH = 64
    }
}
