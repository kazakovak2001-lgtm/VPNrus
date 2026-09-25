package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * B-WL-R6 - what a tolerant schema-2 decode left out of the interpreted
 * manifest. Carried on [SignedManifest] for typed diagnostics only (counts,
 * never wire ids, hosts or metadata) - never a selection input.
 */
data class ManifestTolerance(val ignoredUnknownBindings: Int, val droppedEndpoints: Int) {
    init {
        require(ignoredUnknownBindings >= 0 && droppedEndpoints >= 0) { "negative tolerance count" }
    }

    companion object {
        val NONE = ManifestTolerance(0, 0)
    }
}

/**
 * Wire-level (uninterpreted) schema-2 manifest: transport kinds and roles are
 * raw integers exactly as signed. Produced by [ManifestSchema2Codec.parse]
 * WITHOUT consulting [TransportKind]; lists keep the received order.
 */
data class Schema2WireManifest(
    val manifestVersion: Int,
    val issuedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val signingKeyId: String,
    val endpoints: List<Schema2WireEndpoint>,
)

data class Schema2WireEndpoint(
    val id: String,
    val roleWireIds: List<Int>,
    val region: String,
    val provider: String,
    val asn: Int?,
    val bindings: List<Schema2WireBinding>,
    val relayTo: String?,
)

/** Every binding, known or not, has this one envelope; new kinds carry anything extra in signed [metadata]. */
data class Schema2WireBinding(val wireId: Int, val host: String, val port: Int, val metadata: List<Pair<String, String>>)

/** Result of interpreting verified-or-candidate schema-2 bytes. */
data class Schema2Decoded(val manifest: EndpointManifest, val tolerance: ManifestTolerance)

/**
 * B-WL-R6 - canonical manifest schema 2 (see
 * docs/B_WL_R6_MANIFEST_TRANSPORT_KIND_ROLLOUT.md section 6). Schema 1 stays
 * [ManifestCanonicalizer], strict and unchanged; [SignedManifestCodec]
 * dispatches on the leading schema integer, never by trial decoding.
 *
 * Layout is schema 1's with three differences: the leading integer is 2,
 * roles are written by the explicit [ROLE_WIRE_IDS] table instead of enum
 * ordinal, and canonical order is ENFORCED on read (every list strictly
 * ascending: endpoint ids and metadata keys by unsigned UTF-8 byte order,
 * role and transport wire ids numerically) - so duplicates are rejected and
 * exactly one byte string represents a given wire manifest.
 *
 * Tolerance is limited to one thing: a binding whose wire id this build does
 * not know is structurally validated and then ignored. Everything else that
 * schema 1 rejects is still rejected. The signature always covers the exact
 * received bytes ([SignedManifest.signedCanonicalBytes]); nothing here ever
 * re-serializes a filtered manifest for verification.
 */
object ManifestSchema2Codec {
    const val SCHEMA_VERSION = 2

    /** FROZEN, explicit - equal to the historical EndpointRole ordinals schema 1 writes. */
    val ROLE_WIRE_IDS: Map<EndpointRole, Int> = mapOf(
        EndpointRole.INGRESS to 0,
        EndpointRole.GATEWAY to 1,
        EndpointRole.EXIT to 2,
    )
    private val ROLES_BY_WIRE_ID: Map<Int, EndpointRole> = ROLE_WIRE_IDS.entries.associate { (role, id) -> id to role }

    /** Canonical order for strings: unsigned lexicographic over UTF-8 bytes (= Unicode code point order), independent of JVM String.compareTo. */
    val UTF8_ORDER: Comparator<String> = Comparator { a, b -> compareUtf8(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8)) }

    /**
     * Structural parse only: bounds, exact EOF, strict canonical order. Wire
     * ids are NOT resolved to [TransportKind] here.
     * @throws IllegalArgumentException on any malformation, including truncation.
     */
    fun parse(bytes: ByteArray): Schema2WireManifest = try {
        parseStrict(bytes)
    } catch (e: java.io.EOFException) {
        // Truncated signed bytes are malformed input, not a network error.
        throw IllegalArgumentException("truncated schema-2 manifest")
    }

    private fun parseStrict(bytes: ByteArray): Schema2WireManifest {
        val stream = bytes.inputStream()
        DataInputStream(stream).use { d ->
            val schema = d.readInt()
            require(schema == SCHEMA_VERSION) { "not a schema-2 manifest: $schema" }
            val manifestVersion = d.readInt()
            val issuedAt = d.readLong()
            val expiresAt = d.readLong()
            val signingKeyId = readString(d)
            val endpointCount = d.readInt()
            require(endpointCount in 0..MAX_ENDPOINTS) { "implausible endpoint count: $endpointCount" }
            val endpoints = (0 until endpointCount).map { readEndpoint(d) }
            requireStrictlyAscending(endpoints.map { it.id }, UTF8_ORDER, "endpoint ids")
            val ids = endpoints.map { it.id }.toSet()
            endpoints.forEach { e -> e.relayTo?.let { require(it in ids) { "relay target not in manifest" } } }
            require(stream.available() == 0) { "trailing bytes after schema-2 manifest" }
            return Schema2WireManifest(manifestVersion, issuedAt, expiresAt, signingKeyId, endpoints)
        }
    }

    /** [parse] then [interpret]. The result is an UNTRUSTED candidate until [Ed25519ManifestVerifier] has checked the signature over [bytes]. */
    fun decode(bytes: ByteArray): Schema2Decoded = interpret(parse(bytes))

    /**
     * Maps a wire manifest onto the in-memory model. Bindings with an unknown
     * wire id are dropped and counted. An endpoint left with no known binding
     * is dropped (the model requires at least one), and so, transitively, is
     * any endpoint whose relay target was dropped. Any other model violation
     * still throws.
     */
    fun interpret(wire: Schema2WireManifest): Schema2Decoded {
        var ignoredBindings = 0
        val known = LinkedHashMap<String, Pair<Schema2WireEndpoint, List<EndpointTransportBinding>>>()
        wire.endpoints.forEach { e ->
            val bindings = e.bindings.mapNotNull { b ->
                val kind = TransportKind.fromWireId(b.wireId)
                if (kind == null) {
                    ignoredBindings++
                    null
                } else {
                    EndpointTransportBinding(kind, b.host, b.port, b.metadata.toMap())
                }
            }
            if (bindings.isNotEmpty()) known[e.id] = e to bindings
        }
        do {
            val before = known.size
            known.entries.removeAll { (_, value) -> value.first.relayTo?.let { it !in known } == true }
        } while (known.size != before)
        val endpoints = known.values.map { (e, bindings) ->
            EndpointDescriptor(
                id = EndpointId(e.id),
                roles = e.roleWireIds.map { ROLES_BY_WIRE_ID.getValue(it) }.toSet(),
                region = e.region,
                provider = e.provider,
                asn = e.asn,
                transports = bindings,
                relayTo = e.relayTo?.let(::EndpointId),
            )
        }
        val manifest = EndpointManifest(wire.manifestVersion, wire.issuedAtEpochMillis, wire.expiresAtEpochMillis, endpoints, wire.signingKeyId)
        return Schema2Decoded(manifest, ManifestTolerance(ignoredBindings, wire.endpoints.size - endpoints.size))
    }

    /** Writes [wire] in the order given (no sorting) - so tests can also produce non-canonical input. Use [canonicalWire] for canonical output. */
    fun encode(wire: Schema2WireManifest): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(SCHEMA_VERSION)
            d.writeInt(wire.manifestVersion)
            d.writeLong(wire.issuedAtEpochMillis)
            d.writeLong(wire.expiresAtEpochMillis)
            writeString(d, wire.signingKeyId)
            d.writeInt(wire.endpoints.size)
            wire.endpoints.forEach { e ->
                writeString(d, e.id)
                d.writeInt(e.roleWireIds.size)
                e.roleWireIds.forEach { d.writeInt(it) }
                writeString(d, e.region)
                writeString(d, e.provider)
                d.writeBoolean(e.asn != null)
                d.writeInt(e.asn ?: 0)
                d.writeInt(e.bindings.size)
                e.bindings.forEach { b ->
                    d.writeInt(b.wireId)
                    writeString(d, b.host)
                    d.writeInt(b.port)
                    d.writeInt(b.metadata.size)
                    b.metadata.forEach { (k, v) -> writeString(d, k); writeString(d, v) }
                }
                d.writeBoolean(e.relayTo != null)
                writeString(d, e.relayTo ?: "")
            }
        }
        return out.toByteArray()
    }

    /** Canonical wire form of [manifest] (plus any extra, e.g. unknown, [extraBindings] per endpoint id) with every list in canonical order. */
    fun canonicalWire(manifest: EndpointManifest, extraBindings: Map<String, List<Schema2WireBinding>> = emptyMap()): Schema2WireManifest =
        Schema2WireManifest(
            manifestVersion = manifest.manifestVersion,
            issuedAtEpochMillis = manifest.issuedAtEpochMillis,
            expiresAtEpochMillis = manifest.expiresAtEpochMillis,
            signingKeyId = manifest.signingKeyId,
            endpoints = manifest.endpoints.sortedWith(compareBy(UTF8_ORDER) { it.id.value }).map { e ->
                val bindings = e.transports.map { b -> Schema2WireBinding(b.kind.wireId, b.host, b.port, b.metadata.toList()) } +
                    extraBindings[e.id.value].orEmpty()
                Schema2WireEndpoint(
                    id = e.id.value,
                    roleWireIds = e.roles.map { ROLE_WIRE_IDS.getValue(it) }.sorted(),
                    region = e.region,
                    provider = e.provider,
                    asn = e.asn,
                    bindings = bindings.sortedBy { it.wireId }.map { it.copy(metadata = it.metadata.sortedWith(compareBy(UTF8_ORDER) { p -> p.first })) },
                    relayTo = e.relayTo?.value,
                )
            },
        )

    private fun readEndpoint(d: DataInputStream): Schema2WireEndpoint {
        val id = readString(d)
        val roleCount = d.readInt()
        require(roleCount in 1..ROLE_WIRE_IDS.size) { "implausible role count: $roleCount" }
        val roles = (0 until roleCount).map { d.readInt() }
        roles.forEach { require(it in ROLES_BY_WIRE_ID) { "unknown EndpointRole wire id $it" } }
        requireStrictlyAscending(roles, naturalOrder(), "role wire ids")
        val region = readString(d)
        val provider = readString(d)
        val hasAsn = readStrictBoolean(d)
        val asnValue = d.readInt()
        require(hasAsn || asnValue == 0) { "asn value present without asn flag" }
        val bindingCount = d.readInt()
        require(bindingCount in 1..MAX_TRANSPORTS) { "implausible transport count: $bindingCount" }
        val bindings = (0 until bindingCount).map { readBinding(d) }
        requireStrictlyAscending(bindings.map { it.wireId }, naturalOrder(), "transport wire ids")
        val hasRelay = readStrictBoolean(d)
        val relayTo = readString(d)
        require(hasRelay || relayTo.isEmpty()) { "relay target present without relay flag" }
        // Endpoint-level rules are enforced for every endpoint here, including
        // one interpret() later drops for having only unknown bindings.
        EndpointId(id)
        if (hasRelay) require(EndpointId(relayTo).value != id) { "endpoint relays to itself" }
        require(region.isNotBlank() && provider.isNotBlank()) { "blank endpoint region/provider" }
        if (hasAsn) require(asnValue > 0) { "non-positive asn" }
        return Schema2WireEndpoint(id, roles, region, provider, if (hasAsn) asnValue else null, bindings, if (hasRelay) relayTo else null)
    }

    /** Validated identically for known and unknown wire ids - an unknown binding is ignored only once it is structurally well-formed. */
    private fun readBinding(d: DataInputStream): Schema2WireBinding {
        val wireId = d.readInt()
        require(wireId >= 0) { "negative transport wire id" }
        val host = readString(d)
        require(host.isNotBlank()) { "blank binding host" }
        val port = d.readInt()
        require(port in 1..65535) { "binding port out of range" }
        val metadataCount = d.readInt()
        require(metadataCount in 0..MAX_METADATA) { "implausible metadata count: $metadataCount" }
        val metadata = (0 until metadataCount).map { readString(d) to readString(d) }
        requireStrictlyAscending(metadata.map { it.first }, UTF8_ORDER, "metadata keys")
        return Schema2WireBinding(wireId, host, port, metadata)
    }

    private fun <T> requireStrictlyAscending(values: List<T>, order: Comparator<in T>, what: String) {
        values.zipWithNext().forEach { (a, b) -> require(order.compare(a, b) < 0) { "$what not in strictly ascending canonical order" } }
    }

    /** DataInputStream.readBoolean accepts any non-zero byte; canonical form allows only 0 and 1. */
    private fun readStrictBoolean(d: DataInputStream): Boolean = when (val b = d.readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> throw IllegalArgumentException("non-canonical boolean byte $b")
    }

    private fun writeString(d: DataOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_STRING_BYTES) { "string field too long: ${bytes.size} bytes" }
        d.writeInt(bytes.size)
        d.write(bytes)
    }

    /** Strict UTF-8: malformed sequences are rejected rather than replaced, so decoded text always re-encodes to the signed bytes. */
    private fun readString(d: DataInputStream): String {
        val len = d.readInt()
        require(len in 0..MAX_STRING_BYTES) { "implausible string length: $len" }
        val bytes = ByteArray(len)
        d.readFully(bytes)
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw IllegalArgumentException("invalid UTF-8 in schema-2 string")
        }
    }

    private fun compareUtf8(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val c = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (c != 0) return c
        }
        return a.size - b.size
    }

    private const val MAX_STRING_BYTES = 4096
    private const val MAX_ENDPOINTS = 4096
    private const val MAX_TRANSPORTS = 64
    private const val MAX_METADATA = 64
}
