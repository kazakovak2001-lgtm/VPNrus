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
        val canonicalBytes = ManifestCanonicalizer.canonicalBytes(signed.manifest)
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

    /** @throws IllegalArgumentException / java.io.IOException on any malformed input - never a partial result. */
    fun decode(bytes: ByteArray): SignedManifest {
        DataInputStream(bytes.inputStream()).use { input ->
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
            return SignedManifest(ManifestCanonicalizer.decode(canonicalBytes), signature)
        }
    }
}
