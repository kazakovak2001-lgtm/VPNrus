package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind

/**
 * The signed set of endpoints the client is willing to trust. [manifestVersion]
 * is monotonic - ManifestRollbackGuard rejects any candidate whose version is
 * not strictly greater than what's already stored (see that object's docs).
 * Never constructed with an already-expired or backwards-dated window - see
 * init{} - but VALIDITY (is it expired NOW, does the signature check out) is
 * a separate concern owned by ManifestVerifier, not this data class.
 */
data class EndpointManifest(
    val manifestVersion: Int,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val endpoints: List<EndpointDescriptor>,
    val signingKeyId: String,
) {
    init {
        require(manifestVersion >= 1) { "manifestVersion must be >= 1: $manifestVersion" }
        require(expiresAtEpochMillis > issuedAtEpochMillis) {
            "expiresAtEpochMillis ($expiresAtEpochMillis) must be after issuedAtEpochMillis ($issuedAtEpochMillis)"
        }
        require(signingKeyId.isNotBlank()) { "signingKeyId must not be blank" }
        require(signingKeyId.length <= 64) { "signingKeyId too long: ${signingKeyId.length}" }
        val distinctIds = endpoints.map { it.id }
        require(distinctIds.size == distinctIds.toSet().size) { "EndpointManifest contains a duplicate EndpointId" }
        val ids = distinctIds.toSet()
        endpoints.forEach { e ->
            e.operationalState()
            e.relayTo?.let { require(it in ids) { "EndpointDescriptor ${e.id.value} relays to unknown endpoint ${it.value}" } }
        }
    }
}

/** A manifest plus the raw signature bytes over its canonical encoding - see ManifestCanonicalizer. */
data class SignedManifest(val manifest: EndpointManifest, val signature: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignedManifest) return false
        return manifest == other.manifest && signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int = 31 * manifest.hashCode() + signature.contentHashCode()
}

/**
 * Deterministic, dependency-free binary encoding of an [EndpointManifest] -
 * the exact bytes an offline signer signs and a client verifies against.
 * Field order is fixed and documented inline; nothing here may depend on
 * Map/Set iteration order (both are explicitly sorted before encoding) so
 * the same logical manifest always produces byte-identical output,
 * independent of platform or collection implementation.
 *
 * This is intentionally a plain length-prefixed binary format (the same
 * "4-byte big-endian length + UTF-8 bytes" convention already used by
 * ConnectionOutcomeStore/IdentityFileStore in this codebase) rather than a
 * JSON canonicalization scheme - one fewer external spec to get exactly
 * right for a signature-critical path.
 */
object ManifestCanonicalizer {
    private const val FORMAT_VERSION = 1

    fun canonicalBytes(manifest: EndpointManifest): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).use { d ->
            d.writeInt(FORMAT_VERSION)
            d.writeInt(manifest.manifestVersion)
            d.writeLong(manifest.issuedAtEpochMillis)
            d.writeLong(manifest.expiresAtEpochMillis)
            writeString(d, manifest.signingKeyId)
            val endpointsSorted = manifest.endpoints.sortedBy { it.id.value }
            d.writeInt(endpointsSorted.size)
            endpointsSorted.forEach { writeEndpoint(d, it) }
        }
        return out.toByteArray()
    }

    fun decode(bytes: ByteArray): EndpointManifest {
        java.io.DataInputStream(bytes.inputStream()).use { d ->
            val format = d.readInt()
            require(format == FORMAT_VERSION) { "unsupported manifest format version: $format" }
            val manifestVersion = d.readInt()
            val issuedAt = d.readLong()
            val expiresAt = d.readLong()
            val signingKeyId = readString(d)
            val endpointCount = d.readInt()
            require(endpointCount in 0..MAX_ENDPOINTS) { "implausible endpoint count: $endpointCount" }
            val endpoints = (0 until endpointCount).map { readEndpoint(d) }
            return EndpointManifest(manifestVersion, issuedAt, expiresAt, endpoints, signingKeyId)
        }
    }

    private fun writeEndpoint(d: java.io.DataOutputStream, e: EndpointDescriptor) {
        writeString(d, e.id.value)
        val rolesSorted = e.roles.map { it.ordinal }.sorted()
        d.writeInt(rolesSorted.size)
        rolesSorted.forEach { d.writeInt(it) }
        writeString(d, e.region)
        writeString(d, e.provider)
        d.writeBoolean(e.asn != null)
        d.writeInt(e.asn ?: 0)
        // Known and opaque (unknown-kind) bindings share one ordinal-sorted
        // list - exactly the order the signer wrote them in.
        val transportsSorted = (
            e.transports.map { b -> WireBinding(b.kind.ordinal, b.host, b.port, b.metadata) } +
                e.opaqueTransports.map { b -> WireBinding(b.kindOrdinal, b.host, b.port, b.metadata) }
            ).sortedBy { it.kindOrdinal }
        d.writeInt(transportsSorted.size)
        transportsSorted.forEach { writeBinding(d, it) }
        d.writeBoolean(e.relayTo != null)
        writeString(d, e.relayTo?.value ?: "")
    }

    private fun readEndpoint(d: java.io.DataInputStream): EndpointDescriptor {
        val id = readString(d)
        val roleCount = d.readInt()
        require(roleCount in 0..EndpointRoleCount) { "implausible role count: $roleCount" }
        val roleList = (0 until roleCount).map {
            val ordinal = d.readInt()
            EndpointRole.entries.getOrNull(ordinal) ?: throw IllegalArgumentException("unknown EndpointRole ordinal $ordinal")
        }
        val roles = roleList.toSet()
        // A duplicate role ordinal would silently collapse here - reject
        // rather than accept ambiguous/malformed input. Without this check,
        // decode(bytes-with-a-duplicate) produces an object whose OWN
        // re-canonicalization no longer equals `bytes` (the duplicate is
        // gone), so a manifest legitimately signed over such bytes would
        // fail Ed25519 verification for a confusing reason instead of being
        // rejected outright here.
        require(roles.size == roleList.size) { "duplicate EndpointRole ordinal in encoded endpoint" }
        val region = readString(d)
        val provider = readString(d)
        val hasAsn = d.readBoolean()
        val asnValue = d.readInt()
        val transportCount = d.readInt()
        require(transportCount in 0..MAX_TRANSPORTS) { "implausible transport count: $transportCount" }
        val wire = (0 until transportCount).map { readBinding(d) }
        val transports = wire.mapNotNull { w ->
            TransportKind.entries.getOrNull(w.kindOrdinal)?.let { EndpointTransportBinding(it, w.host, w.port, w.metadata) }
        }
        // Forward compatibility: a kind added by a newer server must not
        // make this build reject the whole signed manifest - keep it opaque
        // (see OpaqueTransportBinding) and simply never use it.
        val opaqueTransports = wire.filter { TransportKind.entries.getOrNull(it.kindOrdinal) == null }
            .map { OpaqueTransportBinding(it.kindOrdinal, it.host, it.port, it.metadata) }
        val hasRelay = d.readBoolean()
        val relayTo = readString(d)
        return EndpointDescriptor(
            id = EndpointId(id),
            roles = roles,
            region = region,
            provider = provider,
            asn = if (hasAsn) asnValue else null,
            transports = transports,
            relayTo = if (hasRelay) EndpointId(relayTo) else null,
            opaqueTransports = opaqueTransports,
        )
    }

    /** One binding exactly as it appears on the wire, whether or not this build knows its kind. */
    private data class WireBinding(val kindOrdinal: Int, val host: String, val port: Int, val metadata: Map<String, String>)

    private fun writeBinding(d: java.io.DataOutputStream, b: WireBinding) {
        d.writeInt(b.kindOrdinal)
        writeString(d, b.host)
        d.writeInt(b.port)
        val metadataSorted = b.metadata.entries.sortedBy { it.key }
        d.writeInt(metadataSorted.size)
        metadataSorted.forEach { (k, v) -> writeString(d, k); writeString(d, v) }
    }

    private fun readBinding(d: java.io.DataInputStream): WireBinding {
        val kindOrdinal = d.readInt()
        require(kindOrdinal >= 0) { "negative TransportKind ordinal $kindOrdinal" }
        val host = readString(d)
        val port = d.readInt()
        val metadataCount = d.readInt()
        require(metadataCount in 0..MAX_METADATA) { "implausible metadata count: $metadataCount" }
        val metadataEntries = (0 until metadataCount).map { readString(d) to readString(d) }
        val metadata = metadataEntries.toMap()
        // Same reasoning as the duplicate-role check above: a duplicate key
        // silently collapses via associate()/toMap() (last write wins),
        // which would make this object's own re-canonicalization diverge
        // from the bytes actually signed - reject instead of accepting
        // ambiguous input.
        require(metadata.size == metadataEntries.size) { "duplicate metadata key in encoded transport binding" }
        return WireBinding(kindOrdinal, host, port, metadata)
    }

    private fun writeString(d: java.io.DataOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_STRING_BYTES) { "string field too long: ${bytes.size} bytes" }
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    private fun readString(d: java.io.DataInputStream): String {
        val len = d.readInt()
        require(len in 0..MAX_STRING_BYTES) { "implausible string length: $len" }
        val bytes = ByteArray(len)
        d.readFully(bytes)
        return String(bytes, Charsets.UTF_8)
    }

    private val EndpointRoleCount = EndpointRole.entries.size
    private const val MAX_STRING_BYTES = 4096
    private const val MAX_ENDPOINTS = 4096
    private const val MAX_TRANSPORTS = 64
    private const val MAX_METADATA = 64
}
