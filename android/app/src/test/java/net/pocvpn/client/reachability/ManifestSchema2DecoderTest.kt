package net.pocvpn.client.reachability

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.transport.TransportKind
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer

/**
 * B-WL-R6 - tolerant schema-2 manifest decoding. Every fixture is generated
 * here, deterministically, with a fixed TEST key (never a production key);
 * nothing here touches gateway/tools or the embedded bootstrap.
 */
class ManifestSchema2DecoderTest {

    @get:Rule val tempFolder = TemporaryFolder()

    private val keyId = "schema2-test-key"
    private val priv = Ed25519PrivateKeyParameters(ByteArray(32) { (it * 7 + 1).toByte() }, 0)
    private val anchors = FixedManifestTrustAnchors(mapOf(TrustedKeyId(keyId) to priv.generatePublicKey().encoded))
    private val issuedAt = 1_000_000L
    private val now = issuedAt + 1

    // --- fixtures ---------------------------------------------------------

    private fun binding(kind: TransportKind, host: String = "203.0.113.${kind.wireId + 1}", metadata: Map<String, String> = emptyMap()) =
        EndpointTransportBinding(kind, host, 443, metadata)

    private fun endpoint(id: String, transports: List<EndpointTransportBinding>, relayTo: String? = null, roles: Set<EndpointRole> = setOf(EndpointRole.GATEWAY)) =
        EndpointDescriptor(EndpointId(id), roles, "eu", "test-provider", 64500, transports, relayTo?.let(::EndpointId))

    /** Every TransportKind this build knows, on one endpoint, plus a second and a relaying endpoint. */
    private fun allKnownManifest(version: Int = 5) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = issuedAt,
        expiresAtEpochMillis = issuedAt + 10_000_000L,
        signingKeyId = keyId,
        endpoints = listOf(
            endpoint("gw-b", TransportKind.entries.map { binding(it, metadata = mapOf("sni" to "example.test", "alpn" to "h2")) }),
            endpoint("gw-d", listOf(binding(TransportKind.AMNEZIA_WG))),
            endpoint("in-f", listOf(binding(TransportKind.TLS_TCP)), relayTo = "gw-b", roles = setOf(EndpointRole.INGRESS)),
        ),
    )

    private fun unknown(wireId: Int, host: String = "198.51.100.9", port: Int = 8443, metadata: List<Pair<String, String>> = listOf("future" to "x")) =
        Schema2WireBinding(wireId, host, port, metadata)

    private fun sign(canonical: ByteArray): ByteArray = Ed25519Signer().run {
        init(true, priv)
        update(canonical, 0, canonical.size)
        generateSignature()
    }

    /** The outer container, built by hand (not via SignedManifestCodec) so the codec is tested against an independent writer. */
    private fun container(canonical: ByteArray, signature: ByteArray = sign(canonical)): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(1)
            d.writeInt(canonical.size)
            d.write(canonical)
            d.writeInt(signature.size)
            d.write(signature)
        }
        return out.toByteArray()
    }

    private fun canonicalOf(manifest: EndpointManifest, extra: Map<String, List<Schema2WireBinding>> = emptyMap()) =
        ManifestSchema2Codec.encode(ManifestSchema2Codec.canonicalWire(manifest, extra))

    private fun verify(signed: SignedManifest) = Ed25519ManifestVerifier().verify(signed, anchors, now)

    private fun decodeAndVerify(container: ByteArray): ManifestVerificationResult = verify(SignedManifestCodec.decode(container))

    private fun assertRejectedAsMalformed(container: ByteArray, what: String) {
        val error = runCatching { SignedManifestCodec.decode(container) }.exceptionOrNull()
        assertTrue("$what must be rejected with IllegalArgumentException (-> MALFORMED), got $error", error is IllegalArgumentException)
    }

    private fun assertSignatureRejected(container: ByteArray, what: String) {
        val decoded = runCatching { SignedManifestCodec.decode(container) }
        if (decoded.isFailure) {
            assertTrue("$what: ${decoded.exceptionOrNull()}", decoded.exceptionOrNull() is IllegalArgumentException)
            return
        }
        val result = verify(decoded.getOrThrow())
        assertTrue("$what must fail verification, got $result", result is ManifestVerificationResult.Invalid)
        assertEquals(what, ManifestVerificationFailureKind.INVALID_SIGNATURE, (result as ManifestVerificationResult.Invalid).kind)
    }

    private fun canonicalSlice(container: ByteArray): ByteArray {
        val len = ByteBuffer.wrap(container, 4, 4).int
        return container.copyOfRange(8, 8 + len)
    }

    /** Offset of the first occurrence of [needle] inside [haystack]. */
    private fun indexOf(haystack: ByteArray, needle: ByteArray): Int =
        (0..haystack.size - needle.size).first { i -> needle.indices.all { haystack[i + it] == needle[it] } }

    private fun flipByteAt(bytes: ByteArray, index: Int) = bytes.copyOf().also { it[index] = (it[index].toInt() xor 0x01).toByte() }

    // --- A: accept ---------------------------------------------------------

    @Test
    fun `A - schema 2 with every known kind decodes, verifies and round-trips byte-for-byte`() {
        val manifest = allKnownManifest()
        val bytes = container(canonicalOf(manifest))
        val signed = SignedManifestCodec.decode(bytes)
        assertEquals(manifest, signed.manifest)
        assertEquals(ManifestTolerance.NONE, signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
        assertArrayEquals(bytes, SignedManifestCodec.encode(signed))
        assertEquals(TransportKind.entries.toSet(), signed.manifest.endpoints.flatMap { e -> e.transports.map { it.kind } }.toSet())
    }

    // --- B: accept, unknown binding ignored ------------------------------

    @Test
    fun `B - an unknown wire id is ignored after verification and every known binding is kept`() {
        val manifest = allKnownManifest()
        val bytes = container(canonicalOf(manifest, mapOf("gw-b" to listOf(unknown(7)))))
        val signed = SignedManifestCodec.decode(bytes)
        assertEquals(manifest, signed.manifest)
        assertEquals(ManifestTolerance(ignoredUnknownBindings = 1, droppedEndpoints = 0), signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
        assertArrayEquals("the signed bytes, unknown binding included, are kept verbatim", canonicalSlice(bytes), signed.signedCanonicalBytes)
        assertArrayEquals(bytes, SignedManifestCodec.encode(signed))
    }

    @Test
    fun `B - several unknown bindings on several endpoints are all ignored`() {
        val manifest = allKnownManifest()
        val extra = mapOf(
            "gw-b" to listOf(unknown(7), unknown(42), unknown(Int.MAX_VALUE)),
            "gw-d" to listOf(unknown(1000, metadata = emptyList())),
        )
        val signed = SignedManifestCodec.decode(container(canonicalOf(manifest, extra)))
        assertEquals(manifest, signed.manifest)
        assertEquals(ManifestTolerance(4, 0), signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
    }

    /**
     * Inside one endpoint canonical order is by wire id, so with ids 0-6 all
     * known, an unknown binding always follows the known ones there. Its
     * position among KNOWN bindings in the byte stream is varied instead by
     * placing it in the first, a middle, or the last endpoint.
     */
    @Test
    fun `B - an unknown binding before, between or after known bindings in the byte stream is ignored`() {
        val manifest = allKnownManifest()
        listOf("gw-b", "gw-d", "in-f").forEach { host ->
            val signed = SignedManifestCodec.decode(container(canonicalOf(manifest, mapOf(host to listOf(unknown(9))))))
            assertEquals(host, manifest, signed.manifest)
            assertEquals(host, 1, signed.tolerance.ignoredUnknownBindings)
            assertEquals(host, ManifestVerificationResult.Valid, verify(signed))
        }
    }

    @Test
    fun `B - endpoints carrying only unknown bindings (first, between, last) are dropped, with any relay onto them`() {
        val manifest = allKnownManifest()
        val base = ManifestSchema2Codec.canonicalWire(manifest)
        fun onlyUnknown(id: String, relayTo: String? = null) =
            Schema2WireEndpoint(id, listOf(1), "eu", "p", null, listOf(unknown(8)), relayTo)
        val wire = base.copy(
            endpoints = (base.endpoints + listOf(onlyUnknown("a-first"), onlyUnknown("gw-c-between"), onlyUnknown("z-last"), onlyUnknown("gw-e", relayTo = "z-last")))
                .sortedWith(compareBy(ManifestSchema2Codec.UTF8_ORDER) { it.id }),
        )
        val signed = SignedManifestCodec.decode(container(ManifestSchema2Codec.encode(wire)))
        assertEquals(manifest, signed.manifest)
        assertEquals(ManifestTolerance(ignoredUnknownBindings = 4, droppedEndpoints = 4), signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
    }

    @Test
    fun `B - a known endpoint relaying onto an endpoint that is dropped is dropped too (fail closed, never a dangling relay)`() {
        val known = EndpointManifest(1, issuedAt, issuedAt + 10_000L, listOf(endpoint("gw", listOf(binding(TransportKind.AMNEZIA_WG)))), keyId)
        val base = ManifestSchema2Codec.canonicalWire(known)
        val wire = base.copy(
            endpoints = listOf(
                Schema2WireEndpoint("exit-future", listOf(2), "eu", "p", null, listOf(unknown(11)), null),
                base.endpoints.single(),
                Schema2WireEndpoint("in-a", listOf(0), "eu", "p", null, listOf(Schema2WireBinding(3, "192.0.2.1", 443, emptyList())), "exit-future"),
            ),
        )
        val signed = SignedManifestCodec.decode(container(ManifestSchema2Codec.encode(wire)))
        assertEquals(listOf(EndpointId("gw")), signed.manifest.endpoints.map { it.id })
        assertEquals(ManifestTolerance(1, 2), signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
    }

    // --- C: SECURITY - an unknown binding is covered by the signature ----

    @Test
    fun `C - modifying an unknown binding after signing is rejected (host, port, metadata, wire id)`() {
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-d" to listOf(unknown(7, host = "198.51.100.77", port = 8443, metadata = listOf("future" to "secretless")))))
        val signature = sign(canonical)
        val hostAt = indexOf(canonical, "198.51.100.77".toByteArray())
        val metaAt = indexOf(canonical, "secretless".toByteArray())
        val portAt = hostAt + "198.51.100.77".length
        val wireIdAt = hostAt - 8 // [wireId:Int][hostLen:Int][host]
        assertEquals(7, ByteBuffer.wrap(canonical, wireIdAt, 4).int)
        assertEquals(8443, ByteBuffer.wrap(canonical, portAt, 4).int)
        val tampered = mapOf(
            "unknown host" to flipByteAt(canonical, hostAt + 3),
            "unknown port" to flipByteAt(canonical, portAt + 3),
            "unknown metadata value" to flipByteAt(canonical, metaAt),
            "unknown wire id 7 -> 6 (now a KNOWN kind)" to flipByteAt(canonical, wireIdAt + 3),
        )
        tampered.forEach { (what, bytes) -> assertSignatureRejected(container(bytes, signature), what) }
        // Control: the untampered bytes with the same signature verify.
        assertEquals(ManifestVerificationResult.Valid, decodeAndVerify(container(canonical, signature)))
    }

    @Test
    fun `C - removing an unknown binding after signing is rejected even though the interpreted manifest is unchanged`() {
        val manifest = allKnownManifest()
        val signedWithUnknown = sign(canonicalOf(manifest, mapOf("gw-d" to listOf(unknown(7)))))
        val stripped = canonicalOf(manifest) // exactly what a "filter then re-serialize" client would verify
        val candidate = SignedManifestCodec.decode(container(stripped, signedWithUnknown))
        assertEquals(manifest, candidate.manifest)
        assertSignatureRejected(container(stripped, signedWithUnknown), "stripped unknown binding")
    }

    @Test
    fun `C - a tampered unknown binding is rejected by the repository and never reaches the LKG store`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7, host = "198.51.100.66"))))
        val signature = sign(canonical)
        val tampered = flipByteAt(canonical, indexOf(canonical, "198.51.100.66".toByteArray()))
        val result = repo.offer(SignedManifestCodec.decode(container(tampered, signature)))
        assertEquals(ManifestUpdateRejectionKind.INVALID_SIGNATURE, (result as ManifestUpdateResult.Rejected).kind)
        assertEquals(null, store.current())
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    // --- D / E: payload and signature tampering --------------------------

    @Test
    fun `D - modifying the known payload after signing is rejected`() {
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7))))
        val signature = sign(canonical)
        val knownHostAt = indexOf(canonical, "203.0.113.1".toByteArray())
        listOf(
            "manifest version" to flipByteAt(canonical, 7),
            "known binding host" to flipByteAt(canonical, knownHostAt + 2),
            "endpoint provider" to flipByteAt(canonical, indexOf(canonical, "test-provider".toByteArray())),
        ).forEach { (what, bytes) -> assertSignatureRejected(container(bytes, signature), what) }
    }

    @Test
    fun `E - modifying the signature is rejected`() {
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7))))
        val signature = sign(canonical)
        listOf(0, 31, 63).forEach { i -> assertSignatureRejected(container(canonical, flipByteAt(signature, i)), "signature byte $i") }
        assertSignatureRejected(container(canonical, ByteArray(64)), "all-zero signature")
    }

    @Test
    fun `E - a candidate whose manifest or tolerance does not match its signed schema-2 bytes is rejected`() {
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7))))
        val genuine = SignedManifestCodec.decode(container(canonical))
        val otherManifest = allKnownManifest(version = 6)
        listOf(
            genuine.copy(manifest = otherManifest),
            genuine.copy(tolerance = ManifestTolerance.NONE),
        ).forEach { forged ->
            val result = verify(forged)
            assertEquals(ManifestVerificationFailureKind.INVALID_SIGNATURE, (result as ManifestVerificationResult.Invalid).kind)
        }
    }

    // --- F: unsupported schema / schema 1 unchanged ----------------------

    @Test
    fun `F - an unsupported canonical schema version is rejected before any interpretation`() {
        val canonical = canonicalOf(allKnownManifest())
        listOf(0, 3, 99, -1, Int.MAX_VALUE).forEach { version ->
            val bytes = canonical.copyOf().also { ByteBuffer.wrap(it, 0, 4).putInt(version) }
            assertRejectedAsMalformed(container(bytes), "schema $version")
        }
        assertRejectedAsMalformed(container(ByteArray(3)), "canonical bytes shorter than the schema marker")
    }

    @Test
    fun `F - schema 1 is still strict - an unknown wire id rejects the whole schema-1 manifest`() {
        val schema1 = ManifestCanonicalizer.canonicalBytes(allKnownManifest())
        // In schema 1 the same binding bytes carry wire id 6 (XRAY_REALITY_XHTTP, the last kind); make it 7.
        val sixAt = indexOf(schema1, "203.0.113.7".toByteArray()) - 8
        assertEquals(6, ByteBuffer.wrap(schema1, sixAt, 4).int)
        val tampered = schema1.copyOf().also { ByteBuffer.wrap(it, sixAt, 4).putInt(7) }
        assertRejectedAsMalformed(container(tampered), "schema-1 unknown wire id")
        // And a genuine schema-1 container still verifies over its re-canonicalization, with no raw bytes attached.
        val signed = SignedManifestCodec.decode(container(schema1))
        assertEquals(null, signed.signedCanonicalBytes)
        assertEquals(ManifestTolerance.NONE, signed.tolerance)
        assertEquals(ManifestVerificationResult.Valid, verify(signed))
    }

    // --- G: duplicates -----------------------------------------------------

    @Test
    fun `G - a duplicate wire id inside one endpoint is rejected (known or unknown)`() {
        val base = ManifestSchema2Codec.canonicalWire(allKnownManifest())
        fun withBindings(bindings: List<Schema2WireBinding>) = base.copy(endpoints = base.endpoints.map { if (it.id == "gw-d") it.copy(bindings = bindings) else it })
        val known = Schema2WireBinding(0, "203.0.113.1", 443, emptyList())
        listOf(
            "duplicate known" to listOf(known, known.copy(host = "203.0.113.2")),
            "duplicate unknown" to listOf(known, unknown(7), unknown(7, host = "198.51.100.10")),
        ).forEach { (what, bindings) -> assertRejectedAsMalformed(container(ManifestSchema2Codec.encode(withBindings(bindings))), what) }
    }

    @Test
    fun `G - duplicate endpoint ids, roles and metadata keys are rejected`() {
        val base = ManifestSchema2Codec.canonicalWire(allKnownManifest())
        val first = base.endpoints.first()
        listOf(
            "duplicate endpoint id" to base.copy(endpoints = listOf(first, first) + base.endpoints.drop(1)),
            "duplicate role" to base.copy(endpoints = listOf(first.copy(roleWireIds = listOf(1, 1))) + base.endpoints.drop(1)),
            "duplicate metadata key in an unknown binding" to base.copy(
                endpoints = listOf(first.copy(bindings = first.bindings + unknown(7, metadata = listOf("k" to "1", "k" to "2")))) + base.endpoints.drop(1),
            ),
        ).forEach { (what, wire) -> assertRejectedAsMalformed(container(ManifestSchema2Codec.encode(wire)), what) }
    }

    // --- H: malformed input fails closed ---------------------------------

    @Test
    fun `H - malformed unknown bindings are rejected, not ignored`() {
        val base = ManifestSchema2Codec.canonicalWire(allKnownManifest())
        fun withUnknown(b: Schema2WireBinding) =
            base.copy(endpoints = base.endpoints.map { if (it.id == "gw-d") it.copy(bindings = it.bindings + b) else it })
        listOf(
            "port 0" to unknown(7, port = 0),
            "port 65536" to unknown(7, port = 65536),
            "blank host" to unknown(7, host = " "),
            "negative wire id" to unknown(-7),
            "metadata keys out of order" to unknown(7, metadata = listOf("b" to "1", "a" to "2")),
            "too many metadata entries" to unknown(7, metadata = (0..64).map { "k%03d".format(it) to "v" }),
        ).forEach { (what, b) -> assertRejectedAsMalformed(container(ManifestSchema2Codec.encode(withUnknown(b))), what) }
    }

    @Test
    fun `H - non-canonical order is rejected (unknown before known, endpoints unsorted, roles unsorted)`() {
        val base = ManifestSchema2Codec.canonicalWire(allKnownManifest())
        val gwD = base.endpoints.single { it.id == "gw-d" }
        listOf(
            "unknown binding placed before a known one" to base.copy(endpoints = base.endpoints.map { if (it === gwD) it.copy(bindings = listOf(unknown(7)) + it.bindings) else it }),
            "endpoints out of order" to base.copy(endpoints = base.endpoints.reversed()),
            "roles out of order" to base.copy(endpoints = base.endpoints.map { if (it === gwD) it.copy(roleWireIds = listOf(2, 1)) else it }),
            "unknown role wire id" to base.copy(endpoints = base.endpoints.map { if (it === gwD) it.copy(roleWireIds = listOf(1, 3)) else it }),
        ).forEach { (what, wire) -> assertRejectedAsMalformed(container(ManifestSchema2Codec.encode(wire)), what) }
    }

    @Test
    fun `H - every truncation, trailing byte and invalid UTF-8 inside the signed bytes is rejected as malformed`() {
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7))))
        (4 until canonical.size).forEach { len -> assertRejectedAsMalformed(container(canonical.copyOf(len)), "truncated to $len") }
        assertRejectedAsMalformed(container(canonical + byteArrayOf(0)), "trailing byte")
        val hostAt = indexOf(canonical, "198.51.100.9".toByteArray())
        assertRejectedAsMalformed(container(canonical.copyOf().also { it[hostAt] = 0xFF.toByte() }), "invalid UTF-8 in unknown host")
        val boolAt = indexOf(canonical, "test-provider".toByteArray()) + "test-provider".length
        assertRejectedAsMalformed(container(canonical.copyOf().also { it[boolAt] = 2 }), "non-canonical boolean")
    }

    // --- canonical ordering (no enum-order dependency) --------------------

    @Test
    fun `canonical layout matches an independently hand-written byte encoding`() {
        val manifest = EndpointManifest(
            3, 10L, 20L,
            listOf(
                EndpointDescriptor(
                    EndpointId("e1"), setOf(EndpointRole.GATEWAY, EndpointRole.INGRESS), "r", "p", null,
                    listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "h", 443, mapOf("z" to "1", "a" to "2"))),
                ),
            ),
            "k",
        )
        val expected = ByteArrayOutputStream().also { out ->
            DataOutputStream(out).use { d ->
                fun str(s: String) { d.writeInt(s.toByteArray().size); d.write(s.toByteArray()) }
                d.writeInt(2); d.writeInt(3); d.writeLong(10L); d.writeLong(20L); str("k")
                d.writeInt(1)
                str("e1"); d.writeInt(2); d.writeInt(0); d.writeInt(1); str("r"); str("p"); d.writeBoolean(false); d.writeInt(0)
                d.writeInt(2)
                d.writeInt(1); str("h"); d.writeInt(443); d.writeInt(2); str("a"); str("2"); str("z"); str("1")
                d.writeInt(77); str("u"); d.writeInt(1); d.writeInt(0)
                d.writeBoolean(false); str("")
            }
        }.toByteArray()
        assertArrayEquals(expected, canonicalOf(manifest, mapOf("e1" to listOf(Schema2WireBinding(77, "u", 1, emptyList())))))
    }

    @Test
    fun `canonical order uses Unicode code point order for strings, not JVM UTF-16 compareTo`() {
        val bmpHigh = "ﬁ" // U+FB01
        val astral = "😀" // U+1F600: UTF-16 sorts it BEFORE U+FB01, code point order AFTER
        assertTrue(astral < bmpHigh)
        val manifest = EndpointManifest(
            1, issuedAt, issuedAt + 10_000L,
            listOf(endpoint(astral, listOf(binding(TransportKind.AMNEZIA_WG))), endpoint(bmpHigh, listOf(binding(TransportKind.AMNEZIA_WG)))),
            keyId,
        )
        val wire = ManifestSchema2Codec.canonicalWire(manifest)
        assertEquals(listOf(bmpHigh, astral), wire.endpoints.map { it.id })
        assertEquals(ManifestVerificationResult.Valid, decodeAndVerify(container(ManifestSchema2Codec.encode(wire))))
        assertRejectedAsMalformed(container(ManifestSchema2Codec.encode(wire.copy(endpoints = wire.endpoints.reversed()))), "UTF-16 order")
    }

    @Test
    fun `role and transport wire ids are explicit tables - never enum declaration order`() {
        assertEquals(mapOf(EndpointRole.INGRESS to 0, EndpointRole.GATEWAY to 1, EndpointRole.EXIT to 2), ManifestSchema2Codec.ROLE_WIRE_IDS)
        assertEquals(EndpointRole.entries.toSet(), ManifestSchema2Codec.ROLE_WIRE_IDS.keys)
        val wire = ManifestSchema2Codec.canonicalWire(allKnownManifest())
        assertEquals(TransportKind.entries.map { it.wireId }.sorted(), wire.endpoints.single { it.id == "gw-b" }.bindings.map { it.wireId })
        val source = File("src/main/java/net/pocvpn/client/reachability/ManifestSchema2Codec.kt").readText()
        assertTrue("schema 2 must never encode by ordinal", !Regex("""\.ordinal\b""").containsMatchIn(source))
        assertTrue("schema 2 must never index enum entries", !Regex("""\.(entries|values\(\))\s*(\.getOrNull\(|\[)""").containsMatchIn(source))
    }

    // --- LKG / fallback ---------------------------------------------------

    private fun bootstrap(): SignedManifest {
        val m = EndpointManifest(1, issuedAt, issuedAt + 10_000_000L, listOf(endpoint("boot", listOf(binding(TransportKind.AMNEZIA_WG)))), keyId)
        return SignedManifestCodec.decode(container(ManifestCanonicalizer.canonicalBytes(m)))
    }

    private fun repository(store: LastKnownGoodManifestStore) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = anchors,
        lkgStore = store,
        bootstrapManifest = bootstrap(),
        nowEpochMillis = { now },
    )

    @Test
    fun `valid schema 2 with an unknown kind is ACCEPTED (not malformed), persisted verbatim, and re-trusted from LKG after restart`() {
        val dir = tempFolder.newFolder()
        val bytes = container(canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7)))))
        val repo = repository(FileLastKnownGoodManifestStore(dir))
        val result = runBlocking { ManifestDistributionClient({ ManifestFetchResult.Fetched(SignedManifestCodec.decode(bytes)) }, repo).refresh() }
        assertTrue("got $result", result is ManifestUpdateResult.Accepted)
        assertArrayEquals("LKG file holds exactly the received container", bytes, File(dir, "endpoint_manifest_lkg.bin").readBytes())

        val restarted = repository(FileLastKnownGoodManifestStore(dir)).trustedState() as TrustedManifestState.Trusted
        assertEquals(ManifestSource.LAST_KNOWN_GOOD, restarted.source)
        assertEquals(allKnownManifest(), restarted.manifest)
        assertEquals(ManifestTolerance(1, 0), restarted.tolerance)
    }

    @Test
    fun `invalid signature, malformed and unsupported-schema candidates keep the existing fallback`() {
        val store = FileLastKnownGoodManifestStore(tempFolder.newFolder())
        val repo = repository(store)
        val canonical = canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7))))

        val badSig = repo.offer(SignedManifestCodec.decode(container(canonical, ByteArray(64))))
        assertEquals(ManifestUpdateRejectionKind.INVALID_SIGNATURE, (badSig as ManifestUpdateResult.Rejected).kind)
        // Malformed / unsupported never become a candidate at all - HttpsRemoteManifestFetcher maps this exception to MALFORMED.
        assertRejectedAsMalformed(container(canonical.copyOf(canonical.size - 1)), "malformed")
        assertRejectedAsMalformed(container(canonical.copyOf().also { ByteBuffer.wrap(it, 0, 4).putInt(3) }), "unsupported schema")

        assertEquals(null, store.current())
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, repo.trustedSource())
    }

    @Test
    fun `a schema-2 LKG tampered on disk is not trusted - falls back to bootstrap`() {
        val dir = tempFolder.newFolder()
        val bytes = container(canonicalOf(allKnownManifest(), mapOf("gw-b" to listOf(unknown(7, host = "198.51.100.55")))))
        assertTrue(repository(FileLastKnownGoodManifestStore(dir)).offer(SignedManifestCodec.decode(bytes)) is ManifestUpdateResult.Accepted)
        val file = File(dir, "endpoint_manifest_lkg.bin")
        file.writeBytes(flipByteAt(bytes, indexOf(bytes, "198.51.100.55".toByteArray())))
        val state = repository(FileLastKnownGoodManifestStore(dir)).trustedState() as TrustedManifestState.Trusted
        assertEquals(ManifestSource.EMBEDDED_BOOTSTRAP, state.source)
        assertNotNull(state.manifest)
    }
}
