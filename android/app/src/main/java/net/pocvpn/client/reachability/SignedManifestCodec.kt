package net.pocvpn.client.reachability

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * B12 - the ONE binary container format for a [SignedManifest] on the wire
 * or on disk: `[formatVersion:Int][canonicalLen:Int][canonicalBytes]
 * [signatureLen:Int][signature]`. Extracted out of
 * [FileLastKnownGoodManifestStore] (which used this shape privately since
 * B11) so the SAME encode/decode logic backs BOTH local LKG persistence and
 * the B12 remote manifest-distribution download - one format, one place it
 * could ever drift out of self-consistency, never two independently
 * maintained binary parsers for what is logically the same artifact.
 *
 * This is NOT [ManifestCanonicalizer] - that format is what gets SIGNED
 * (`canonicalBytes`, embedded here as an opaque, already-encoded blob).
 * This format is the outer container that also carries the signature bytes
 * alongside it.
 */
object SignedManifestCodec {
    private const val FORMAT_VERSION = 1
    private const val MAX_CANONICAL_BYTES = 1_000_000
    private const val MAX_SIGNATURE_BYTES = 256

    fun encode(signed: SignedManifest): ByteArray {
        // Schema 2: the exact signed bytes, verbatim - never a re-encoding of the filtered manifest.
        val canonicalBytes = signed.signedCanonicalBytes ?: ManifestCanonicalizer.canonicalBytes(signed.manifest)
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeInt(FORMAT_VERSION)
            d.writeInt(canonicalBytes.size)
            d.write(canonicalBytes)
            d.writeInt(signed.signature.size)
            d.write(signed.signature)
        }
        return out.toByteArray()
    }

    /**
     * @throws IllegalArgumentException / java.io.IOException on any
     * malformed input - never a partial result. Requires EXACT container
     * consumption (PR #24 audit fix): [bytes] must contain nothing beyond
     * the signature - any trailing byte, however small, is rejected. A
     * container is a complete, self-describing artifact, never a prefix of
     * a longer stream; silently ignoring trailing bytes would let extra
     * (possibly attacker- or bug-appended) data ride along undetected in
     * whatever [bytes] came from (a downloaded HTTP response, an on-disk
     * file) without ever being surfaced.
     */
    fun decode(bytes: ByteArray): SignedManifest {
        val stream = bytes.inputStream()
        DataInputStream(stream).use { input ->
            val version = input.readInt()
            require(version == FORMAT_VERSION) { "unsupported signed-manifest container format: $version" }
            val canonicalLen = input.readInt()
            require(canonicalLen in 0..MAX_CANONICAL_BYTES) { "implausible canonical manifest length: $canonicalLen" }
            val canonicalBytes = ByteArray(canonicalLen)
            input.readFully(canonicalBytes)
            val sigLen = input.readInt()
            require(sigLen in 0..MAX_SIGNATURE_BYTES) { "implausible signature length: $sigLen" }
            val signature = ByteArray(sigLen)
            input.readFully(signature)
            require(stream.available() == 0) { "trailing bytes after signed-manifest container (expected EOF): ${stream.available()} extra byte(s)" }
            return decodeCanonical(canonicalBytes, signature)
        }
    }

    /**
     * B-WL-R6 - explicit dispatch on the canonical schema integer (the first
     * 4 bytes of the signed bytes, so the marker itself is signed). Never
     * "try schema 2 if schema 1 fails". Schema 1 is the unchanged strict
     * decoder (an unknown transport wire id still rejects the manifest);
     * any other value is unsupported and rejected.
     */
    private fun decodeCanonical(canonicalBytes: ByteArray, signature: ByteArray): SignedManifest {
        require(canonicalBytes.size >= 4) { "canonical manifest too short for a schema marker" }
        return when (val schema = java.nio.ByteBuffer.wrap(canonicalBytes, 0, 4).int) {
            SCHEMA_1 -> SignedManifest(ManifestCanonicalizer.decode(canonicalBytes), signature)
            ManifestSchema2Codec.SCHEMA_VERSION -> {
                val decoded = ManifestSchema2Codec.decode(canonicalBytes)
                SignedManifest(decoded.manifest, signature, canonicalBytes.copyOf(), decoded.tolerance)
            }
            else -> throw IllegalArgumentException("unsupported canonical manifest schema: $schema")
        }
    }

    private const val SCHEMA_1 = 1
}
