package net.pocvpn.client.reachability

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
        val transportsSorted = e.transports.sortedBy { it.kind.ordinal }
        d.writeInt(transportsSorted.size)
        transportsSorted.forEach { writeBinding(d, it) }
        d.writeBoolean(e.relayTo != null)
        writeString(d, e.relayTo?.value ?: "")
    }

    private fun readEndpoint(d: java.io.DataInputStream): EndpointDescriptor {
        val id = readString(d)
        val roleCount = d.readInt()
        require(roleCount in 0..EndpointRoleCount) { "implausible role count: $roleCount" }
        val roles = (0 until roleCount).map {
            val ordinal = d.readInt()
            EndpointRole.entries.getOrNull(ordinal) ?: throw IllegalArgumentException("unknown EndpointRole ordinal $ordinal")
        }.toSet()
        val region = readString(d)
        val provider = readString(d)
        val hasAsn = d.readBoolean()
        val asnValue = d.readInt()
        val transportCount = d.readInt()
        require(transportCount in 0..MAX_TRANSPORTS) { "implausible transport count: $transportCount" }
        val transports = (0 until transportCount).map { readBinding(d) }
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
        )
    }

    private fun writeBinding(d: java.io.DataOutputStream, b: EndpointTransportBinding) {
        d.writeInt(b.kind.ordinal)
        writeString(d, b.host)
        d.writeInt(b.port)
        val metadataSorted = b.metadata.entries.sortedBy { it.key }
        d.writeInt(metadataSorted.size)
        metadataSorted.forEach { (k, v) -> writeString(d, k); writeString(d, v) }
    }

    private fun readBinding(d: java.io.DataInputStream): EndpointTransportBinding {
        val kindOrdinal = d.readInt()
        val kind = net.pocvpn.client.transport.TransportKind.entries.getOrNull(kindOrdinal)
            ?: throw IllegalArgumentException("unknown TransportKind ordinal $kindOrdinal")
        val host = readString(d)
        val port = d.readInt()
        val metadataCount = d.readInt()
        require(metadataCount in 0..MAX_METADATA) { "implausible metadata count: $metadataCount" }
        val metadata = (0 until metadataCount).associate { readString(d) to readString(d) }
        return EndpointTransportBinding(kind, host, port, metadata)
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
