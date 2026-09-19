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
 *
 * ## Post-verification immutability (PR #92 correction)
 *
 * Every ByteArray-bearing field below (nonce, bootstrapCapabilityHint,
 * ActivationBundleRef.contentHash, SignedActivationEnvelope.signature) and
 * [ActivationEnvelope.bootstrapEndpointHints] are defensively copied ON THE
 * WAY IN (so mutating a caller's own source array/list after construction
 * can never change an already-built/already-verified object) and exposed
 * only through a computed property that copies ON THE WAY OUT (so mutating
 * an array obtained from an accessor can never change internal state
 * either). A Kotlin `val ByteArray` is NOT immutable - only a reference is
 * fixed, the underlying bytes remain fully mutable - so this had to be done
 * with plain (non-`data`) classes holding private backing fields, since a
 * `data class`'s primary-constructor properties cannot transform their
 * input before storing it. See ActivationEnvelopeImmutabilityTest for the
 * regression coverage this closes.
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
 * not print them either. Backed by an immutable Kotlin `String`, so unlike
 * the ByteArray-bearing fields elsewhere in this file, no defensive copy is
 * needed here.
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
        /** Generous headroom over today's 43-char token_urlsafe(32) output for future rotation. ASCII-only charset, so this is also the exact UTF-8 byte-length bound the wire parser enforces - no char/byte asymmetry possible. */
        const val MAX_LENGTH = 256
    }
}

/**
 * Identifies which activation-issuer public key must verify an
 * [ActivationEnvelope]. Never a manifest signing-key id - see
 * [ActivationIssuerKeyId]. [MAX_LENGTH_BYTES] bounds the UTF-8 BYTE length
 * (not the Kotlin/UTF-16 character count) so this can never accept a value
 * whose encoded form is longer than what [ActivationEnvelopeCanonicalizer]'s
 * wire parser allows - see PR #92's byte-length-symmetry correction.
 */
data class ActivationIssuerKeyId(val value: String) {
    init {
        require(value.isNotBlank()) { "issuerKeyId must not be blank" }
        require(value.toByteArray(Charsets.UTF_8).size <= MAX_LENGTH_BYTES) {
            "issuerKeyId exceeds max UTF-8 byte length ($MAX_LENGTH_BYTES)"
        }
    }

    companion object {
        const val MAX_LENGTH_BYTES = 64
    }
}

/**
 * Informational cross-reference to a separately-signed SignedBootstrapBundle
 * (not implemented in B56-1). NEVER carries a host/port/network fact - only
 * a manifest version number and a content hash that a client can use to
 * confirm "this is the bundle the envelope was issued alongside", nothing
 * more.
 *
 * [contentHash] is defensively copied from the constructor argument and
 * exposed only through a copying accessor - see this file's class docs on
 * post-verification immutability.
 */
class ActivationBundleRef(val manifestVersion: Int, contentHash: ByteArray) {
    private val contentHashBytes: ByteArray = contentHash.copyOf()

    /** Always a fresh copy - mutating the returned array never affects this instance. */
    val contentHash: ByteArray get() = contentHashBytes.copyOf()

    init {
        require(manifestVersion >= 1) { "manifestVersion must be >= 1: $manifestVersion" }
        require(contentHashBytes.size == CONTENT_HASH_LENGTH) { "contentHash must be exactly $CONTENT_HASH_LENGTH bytes (SHA-256): ${contentHashBytes.size}" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ActivationBundleRef) return false
        return manifestVersion == other.manifestVersion && contentHashBytes.contentEquals(other.contentHashBytes)
    }

    override fun hashCode(): Int = 31 * manifestVersion + contentHashBytes.contentHashCode()
    override fun toString(): String = "ActivationBundleRef(manifestVersion=$manifestVersion, contentHash=<${contentHashBytes.size} bytes>)"

    companion object {
        /** Fixed hash format: SHA-256. */
        const val CONTENT_HASH_LENGTH = 32
    }
}

/**
 * The activation authority's signed payload. Every field listed here is
 * covered by [signature] via [ActivationEnvelopeCanonicalizer] - see
 * ActivationEnvelopeVerifierTest for proof that mutating any one of them
 * invalidates the signature.
 *
 * [bootstrapEndpointHints] and [bootstrapCapabilityHint] are NON-authoritative:
 * they may only reorder/accelerate use of endpoints the client already
 * trusts via a separately-verified manifest, and this layer does not
 * interpret [bootstrapCapabilityHint] at all (bytes are preserved exactly,
 * size-bounded, and treated as sensitive).
 *
 * Deliberately NOT a `data class`: [nonce], [bootstrapCapabilityHint], and
 * [bootstrapEndpointHints] are defensively copied from whatever the caller
 * passed in and exposed only through copying accessors (see this file's
 * class docs on post-verification immutability) - a `data class` cannot do
 * this because its primary-constructor properties cannot transform their
 * input before storing it. [copy] is hand-written below to keep the same
 * call-site ergonomics tests rely on.
 */
class ActivationEnvelope(
    val activationId: ActivationId,
    val credential: ActivationCredential,
    val issuedAtEpochMillis: Long,
    val notBeforeEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val bootstrapBundleRef: ActivationBundleRef?,
    bootstrapEndpointHints: List<EndpointId>,
    bootstrapCapabilityHint: ByteArray?,
    nonce: ByteArray,
    val issuerKeyId: ActivationIssuerKeyId,
) {
    private val hintsList: List<EndpointId> = bootstrapEndpointHints.toList()
    private val capabilityHintBytes: ByteArray? = bootstrapCapabilityHint?.copyOf()
    private val nonceBytes: ByteArray = nonce.copyOf()

    /** Order-preserving, immutable snapshot taken at construction time - mutating a caller-owned source list afterward never affects this instance. */
    val bootstrapEndpointHints: List<EndpointId> get() = hintsList

    /** Always a fresh copy, or null - mutating the returned array never affects this instance. */
    val bootstrapCapabilityHint: ByteArray? get() = capabilityHintBytes?.copyOf()

    /** Always a fresh copy - mutating the returned array never affects this instance. */
    val nonce: ByteArray get() = nonceBytes.copyOf()

    init {
        require(notBeforeEpochMillis < expiresAtEpochMillis) {
            "notBeforeEpochMillis ($notBeforeEpochMillis) must be before expiresAtEpochMillis ($expiresAtEpochMillis)"
        }
        require(nonceBytes.size == NONCE_LENGTH) { "nonce must be exactly $NONCE_LENGTH bytes: ${nonceBytes.size}" }
        require(hintsList.size <= MAX_ENDPOINT_HINTS) {
            "too many bootstrapEndpointHints (${hintsList.size} > $MAX_ENDPOINT_HINTS)"
        }
        val distinctHints = hintsList.toSet()
        require(distinctHints.size == hintsList.size) { "bootstrapEndpointHints contains a duplicate EndpointId" }
        // B56-local boundary (PR #92 correction): EndpointId itself allows up
        // to 128 UTF-16 characters, which for multi-byte text can exceed what
        // ActivationEnvelopeCanonicalizer's wire parser accepts per hint
        // (MAX_ENDPOINT_HINT_UTF8_BYTES UTF-8 bytes). Enforced HERE, not by
        // narrowing EndpointId's own global semantics (used elsewhere for
        // manifest endpoints too), so every constructible ActivationEnvelope
        // is guaranteed to round-trip through encode/decode.
        hintsList.forEach { hint ->
            val byteLength = hint.value.toByteArray(Charsets.UTF_8).size
            require(byteLength <= MAX_ENDPOINT_HINT_UTF8_BYTES) {
                "bootstrapEndpointHint '${hint.value}' exceeds max UTF-8 byte length ($MAX_ENDPOINT_HINT_UTF8_BYTES): $byteLength"
            }
        }
        capabilityHintBytes?.let {
            require(it.size <= MAX_CAPABILITY_HINT_BYTES) { "bootstrapCapabilityHint exceeds max length ($MAX_CAPABILITY_HINT_BYTES): ${it.size}" }
        }
    }

    /** Mirrors `data class` copy() ergonomics without the immutability hole a real `data class` would reopen here - reads through the copying accessors above, so the new instance never aliases this one's backing arrays/list. */
    fun copy(
        activationId: ActivationId = this.activationId,
        credential: ActivationCredential = this.credential,
        issuedAtEpochMillis: Long = this.issuedAtEpochMillis,
        notBeforeEpochMillis: Long = this.notBeforeEpochMillis,
        expiresAtEpochMillis: Long = this.expiresAtEpochMillis,
        bootstrapBundleRef: ActivationBundleRef? = this.bootstrapBundleRef,
        bootstrapEndpointHints: List<EndpointId> = this.bootstrapEndpointHints,
        bootstrapCapabilityHint: ByteArray? = this.bootstrapCapabilityHint,
        nonce: ByteArray = this.nonce,
        issuerKeyId: ActivationIssuerKeyId = this.issuerKeyId,
    ): ActivationEnvelope = ActivationEnvelope(
        activationId, credential, issuedAtEpochMillis, notBeforeEpochMillis, expiresAtEpochMillis,
        bootstrapBundleRef, bootstrapEndpointHints, bootstrapCapabilityHint, nonce, issuerKeyId,
    )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ActivationEnvelope) return false
        return activationId == other.activationId &&
            credential == other.credential &&
            issuedAtEpochMillis == other.issuedAtEpochMillis &&
            notBeforeEpochMillis == other.notBeforeEpochMillis &&
            expiresAtEpochMillis == other.expiresAtEpochMillis &&
            bootstrapBundleRef == other.bootstrapBundleRef &&
            hintsList == other.hintsList &&
            (capabilityHintBytes?.contentEquals(other.capabilityHintBytes ?: ByteArray(0)) ?: (other.capabilityHintBytes == null)) &&
            nonceBytes.contentEquals(other.nonceBytes) &&
            issuerKeyId == other.issuerKeyId
    }

    override fun hashCode(): Int {
        var result = activationId.hashCode()
        result = 31 * result + credential.hashCode()
        result = 31 * result + issuedAtEpochMillis.hashCode()
        result = 31 * result + notBeforeEpochMillis.hashCode()
        result = 31 * result + expiresAtEpochMillis.hashCode()
        result = 31 * result + (bootstrapBundleRef?.hashCode() ?: 0)
        result = 31 * result + hintsList.hashCode()
        result = 31 * result + (capabilityHintBytes?.contentHashCode() ?: 0)
        result = 31 * result + nonceBytes.contentHashCode()
        result = 31 * result + issuerKeyId.hashCode()
        return result
    }

    /** Never prints [credential] or [bootstrapCapabilityHint] contents - both are sensitive. */
    override fun toString(): String =
        "ActivationEnvelope(activationId=$activationId, credential=REDACTED, issuedAtEpochMillis=$issuedAtEpochMillis, " +
            "notBeforeEpochMillis=$notBeforeEpochMillis, expiresAtEpochMillis=$expiresAtEpochMillis, " +
            "bootstrapBundleRef=$bootstrapBundleRef, bootstrapEndpointHints=$hintsList, " +
            "bootstrapCapabilityHint=${if (capabilityHintBytes != null) "<${capabilityHintBytes.size} bytes REDACTED>" else "null"}, " +
            "nonce=<${nonceBytes.size} bytes>, issuerKeyId=$issuerKeyId)"

    companion object {
        /** Architecture-approved size - see docs/RESILIENT_BOOTSTRAP_ACTIVATION_ARCHITECTURE.md section 6. Local dedupe/import metadata only, NOT a replay-prevention security boundary. */
        const val NONCE_LENGTH = 16
        const val MAX_ENDPOINT_HINTS = 32
        const val MAX_CAPABILITY_HINT_BYTES = 4096

        /** Matches [ActivationEnvelopeCanonicalizer]'s own per-hint wire cap exactly - see this class's init{} and PR #92's byte-length-symmetry correction. */
        const val MAX_ENDPOINT_HINT_UTF8_BYTES = 128
    }
}

/**
 * An [ActivationEnvelope] plus the raw Ed25519 signature bytes over its
 * canonical encoding - see [ActivationEnvelopeCanonicalizer]. [signature] is
 * defensively copied in and exposed only through a copying accessor - see
 * [ActivationEnvelope]'s class docs on post-verification immutability.
 */
class SignedActivationEnvelope(val envelope: ActivationEnvelope, signature: ByteArray) {
    private val signatureBytes: ByteArray = signature.copyOf()

    /** Always a fresh copy - mutating the returned array never affects this instance. */
    val signature: ByteArray get() = signatureBytes.copyOf()

    init {
        require(signatureBytes.size == SIGNATURE_LENGTH) { "signature must be exactly $SIGNATURE_LENGTH bytes: ${signatureBytes.size}" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedActivationEnvelope) return false
        return envelope == other.envelope && signatureBytes.contentEquals(other.signatureBytes)
    }

    override fun hashCode(): Int = 31 * envelope.hashCode() + signatureBytes.contentHashCode()

    companion object {
        const val SIGNATURE_LENGTH = 64
    }
}
