package net.pocvpn.client.reachability

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Durable last-known-good (LKG) manifest storage. The invariant this
 * interface exists to enforce: only a manifest that has ALREADY passed
 * [ManifestVerifier] may ever be written here (see
 * EndpointManifestRepository, the only real caller of [store]) - this type
 * itself does not re-verify signatures, but it DOES enforce monotonic
 * version ordering on every write (see [ManifestRollbackGuard]), so even a
 * caller bug can't silently roll the stored manifest backwards.
 */
interface LastKnownGoodManifestStore {
    fun current(): SignedManifest?

    /** Returns true if [candidate] was stored (strictly newer version); false if rejected as a rollback. */
    fun store(candidate: SignedManifest): Boolean
}

/** Pure, deterministic rollback rule - never allows equal-or-older to replace what's stored. */
object ManifestRollbackGuard {
    fun isAcceptableReplacement(current: EndpointManifest?, candidate: EndpointManifest): Boolean =
        current == null || candidate.manifestVersion > current.manifestVersion
}

/**
 * File-backed LKG store. Same atomic tmp-file + [Files.move] replace pattern
 * as ConnectionOutcomeStore, and the same "corrupted/malformed on disk ->
 * treated as absent, never crashes and never partially loads" discipline as
 * IdentityFileStore - see [current]'s catch clauses.
 */
class FileLastKnownGoodManifestStore(
    private val directory: File,
    private val fileName: String = "endpoint_manifest_lkg.bin",
) : LastKnownGoodManifestStore {

    private val file: File get() = File(directory, fileName)
    private val lock = Any()

    @Volatile private var cached: SignedManifest? = readFromDisk()

    override fun current(): SignedManifest? = cached

    override fun store(candidate: SignedManifest): Boolean {
        synchronized(lock) {
            if (!ManifestRollbackGuard.isAcceptableReplacement(cached?.manifest, candidate.manifest)) return false
            writeToDisk(candidate)
            cached = candidate
            return true
        }
    }

    private fun readFromDisk(): SignedManifest? {
        if (!file.exists()) return null
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) return null
                val canonicalLen = input.readInt()
                require(canonicalLen in 0..MAX_CANONICAL_BYTES) { "implausible canonical manifest length: $canonicalLen" }
                val canonicalBytes = ByteArray(canonicalLen)
                input.readFully(canonicalBytes)
                val sigLen = input.readInt()
                require(sigLen in 0..MAX_SIGNATURE_BYTES) { "implausible signature length: $sigLen" }
                val signature = ByteArray(sigLen)
                input.readFully(signature)
                SignedManifest(ManifestCanonicalizer.decode(canonicalBytes), signature)
            }
        } catch (e: java.io.IOException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private fun writeToDisk(signed: SignedManifest) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val canonicalBytes = ManifestCanonicalizer.canonicalBytes(signed.manifest)
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                out.writeInt(canonicalBytes.size)
                out.write(canonicalBytes)
                out.writeInt(signed.signature.size)
                out.write(signed.signature)
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace LKG manifest file", e)
        }
    }

    private companion object {
        const val FORMAT_VERSION = 1
        const val MAX_CANONICAL_BYTES = 1_000_000
        const val MAX_SIGNATURE_BYTES = 256
    }
}
