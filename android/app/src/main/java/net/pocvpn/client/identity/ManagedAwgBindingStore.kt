package net.pocvpn.client.identity

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.pocvpn.client.vpn.config.ProductionGatewayId
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Base64
import java.util.zip.CRC32

/**
 * Phase A - non-secret fingerprint of a managed AWG public key: SHA-256 over
 * the RAW 32 key bytes (not the base64 text, so two encodings of the same key
 * can never disagree), first 16 lowercase hex characters.
 */
object ManagedAwgKeyFingerprint {
    const val LENGTH = 16
    private const val WG_KEY_BYTES = 32
    private val HEX = Regex("^[0-9a-f]{$LENGTH}$")

    /** @throws IllegalArgumentException if [publicKeyBase64] is not a 32-byte base64 key. */
    fun of(publicKeyBase64: String): String {
        val raw = try {
            Base64.getDecoder().decode(publicKeyBase64.trim())
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("public key is not valid base64", e)
        }
        require(raw.size == WG_KEY_BYTES) { "public key must be $WG_KEY_BYTES bytes, was ${raw.size}" }
        val digest = MessageDigest.getInstance("SHA-256").digest(raw)
        return digest.joinToString("") { "%02x".format(it) }.substring(0, LENGTH)
    }

    fun isWellFormed(fingerprint: String): Boolean = HEX.matches(fingerprint)
}

sealed class ManagedAwgBindingLoadResult {
    /** No committed binding file. A leftover temp file never counts as committed state. */
    object Absent : ManagedAwgBindingLoadResult()
    data class Valid(val bindings: Map<ProductionGatewayId, String>) : ManagedAwgBindingLoadResult()
    /** Present but not trustworthy - never treated as an empty valid map. */
    data class Unreadable(val reason: String) : ManagedAwgBindingLoadResult()
}

/** Result of reading the CURRENT managed key without ever creating one. */
sealed class ManagedKeyPeek {
    data class Present(val publicKeyBase64: String) : ManagedKeyPeek()
    object Absent : ManagedKeyPeek()
    data class Unavailable(val reason: String) : ManagedKeyPeek()
}

sealed class ManagedAwgBindingUpdateResult {
    object Updated : ManagedAwgBindingUpdateResult()
    /** The activation's key is no longer the current managed key - nothing written. */
    object FingerprintMismatch : ManagedAwgBindingUpdateResult()
    /** No usable current managed key - nothing written. */
    data class IdentityUnavailable(val reason: String) : ManagedAwgBindingUpdateResult()
    /** Existing file is unreadable - deliberately NOT overwritten by a per-gateway update. */
    data class StoreUnreadable(val reason: String) : ManagedAwgBindingUpdateResult()
    data class WriteFailed(val reason: String) : ManagedAwgBindingUpdateResult()
}

sealed class ManagedAwgBindingRemoveResult {
    /** The gateway is confirmed unbound (it was removed, or was never bound). */
    object Removed : ManagedAwgBindingRemoveResult()
    /** Existing file is unreadable - left untouched, never treated as empty. */
    data class StoreUnreadable(val reason: String) : ManagedAwgBindingRemoveResult()
    data class WriteFailed(val reason: String) : ManagedAwgBindingRemoveResult()
}

sealed class ManagedAwgBindingDeleteResult {
    object Deleted : ManagedAwgBindingDeleteResult()
    data class Failed(val reason: String) : ManagedAwgBindingDeleteResult()
}

/**
 * Phase A - per-gateway map `gateway -> managed AWG public key fingerprint`
 * recording which key each stored AWG tunnel identity was issued to. It is the
 * ONLY local evidence that may authorize AWG use of a stored tunnel IP (see
 * [ManagedAwgEligibility]); tunnel-IP presence alone never does.
 *
 * Deliberately has no "adopt"/migration operation: a binding is created only
 * by [updateGateway], whose caller must be a successful activation commit.
 */
interface ManagedAwgBindingStore {
    suspend fun read(): ManagedAwgBindingLoadResult

    /**
     * Binds [gatewayId] to [activationFingerprint] only if it still equals the
     * fingerprint of [currentKey] at write time. [currentKey] is evaluated
     * inside this store's lock, so the check and the write are serialized
     * against every other binding update/delete - but NOT against a managed
     * key change made outside this store (see the Phase A report).
     */
    suspend fun updateGateway(
        gatewayId: ProductionGatewayId,
        activationFingerprint: String,
        currentKey: suspend () -> ManagedKeyPeek,
    ): ManagedAwgBindingUpdateResult

    /**
     * Unbinds ONE gateway by atomically rewriting the file without it; other
     * gateways' bindings are kept. An unreadable file is reported, not rewritten.
     */
    suspend fun removeGateway(gatewayId: ProductionGatewayId): ManagedAwgBindingRemoveResult

    suspend fun deleteAll(): ManagedAwgBindingDeleteResult
}

class FileManagedAwgBindingStore(
    private val directory: File,
    private val fileName: String = "managed_awg_binding.bin",
) : ManagedAwgBindingStore {

    private val lock = Mutex()
    private val file: File get() = File(directory, fileName)
    private val tmp: File get() = File(directory, "$fileName.tmp")

    override suspend fun read(): ManagedAwgBindingLoadResult = lock.withLock { readUnlocked() }

    override suspend fun updateGateway(
        gatewayId: ProductionGatewayId,
        activationFingerprint: String,
        currentKey: suspend () -> ManagedKeyPeek,
    ): ManagedAwgBindingUpdateResult = lock.withLock {
        val currentFingerprint = when (val peek = currentKey()) {
            is ManagedKeyPeek.Present -> try {
                ManagedAwgKeyFingerprint.of(peek.publicKeyBase64)
            } catch (e: IllegalArgumentException) {
                return@withLock ManagedAwgBindingUpdateResult.IdentityUnavailable("current key malformed")
            }
            ManagedKeyPeek.Absent -> return@withLock ManagedAwgBindingUpdateResult.IdentityUnavailable("no managed key")
            is ManagedKeyPeek.Unavailable -> return@withLock ManagedAwgBindingUpdateResult.IdentityUnavailable(peek.reason)
        }
        if (!ManagedAwgKeyFingerprint.isWellFormed(activationFingerprint) || activationFingerprint != currentFingerprint) {
            return@withLock ManagedAwgBindingUpdateResult.FingerprintMismatch
        }
        val existing = when (val loaded = readUnlocked()) {
            ManagedAwgBindingLoadResult.Absent -> emptyMap()
            is ManagedAwgBindingLoadResult.Valid -> loaded.bindings
            is ManagedAwgBindingLoadResult.Unreadable -> return@withLock ManagedAwgBindingUpdateResult.StoreUnreadable(loaded.reason)
        }
        try {
            writeUnlocked(existing + (gatewayId to activationFingerprint))
            ManagedAwgBindingUpdateResult.Updated
        } catch (e: IOException) {
            ManagedAwgBindingUpdateResult.WriteFailed(e.message ?: e.javaClass.simpleName)
        }
    }

    override suspend fun removeGateway(gatewayId: ProductionGatewayId): ManagedAwgBindingRemoveResult = lock.withLock {
        val existing = when (val loaded = readUnlocked()) {
            ManagedAwgBindingLoadResult.Absent -> return@withLock ManagedAwgBindingRemoveResult.Removed
            is ManagedAwgBindingLoadResult.Valid -> loaded.bindings
            is ManagedAwgBindingLoadResult.Unreadable -> return@withLock ManagedAwgBindingRemoveResult.StoreUnreadable(loaded.reason)
        }
        if (gatewayId !in existing) return@withLock ManagedAwgBindingRemoveResult.Removed
        try {
            // Same tmp + fsync + atomic-move path as updateGateway; an empty map is a
            // valid committed file, so the store never passes through an "absent" gap.
            writeUnlocked(existing - gatewayId)
            ManagedAwgBindingRemoveResult.Removed
        } catch (e: IOException) {
            ManagedAwgBindingRemoveResult.WriteFailed(e.message ?: e.javaClass.simpleName)
        }
    }

    override suspend fun deleteAll(): ManagedAwgBindingDeleteResult = lock.withLock {
        tmp.delete()
        if (file.exists() && !file.delete()) return@withLock ManagedAwgBindingDeleteResult.Failed("could not delete binding file")
        if (file.exists()) ManagedAwgBindingDeleteResult.Failed("binding file still present") else ManagedAwgBindingDeleteResult.Deleted
    }

    private fun readUnlocked(): ManagedAwgBindingLoadResult {
        // Only the committed target is authoritative - a leftover tmp from an
        // interrupted write is ignored here (and replaced by the next write).
        if (!file.exists()) return ManagedAwgBindingLoadResult.Absent
        val bytes = try {
            file.readBytes()
        } catch (e: IOException) {
            return ManagedAwgBindingLoadResult.Unreadable("unreadable binding file: ${e.javaClass.simpleName}")
        }
        return decode(bytes)
    }

    private fun writeUnlocked(bindings: Map<ProductionGatewayId, String>) {
        if (!directory.isDirectory && !directory.mkdirs()) throw IOException("cannot create binding directory")
        val bytes = encode(bindings)
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.flush()
                out.fd.sync()
            }
            // Same REPLACE_EXISTING + ATOMIC_MOVE discipline as the other
            // file stores - the previous target stays intact until the move.
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: IOException) {
            tmp.delete()
            throw IOException("failed to persist managed AWG binding", e)
        }
    }

    internal companion object {
        val MAGIC = byteArrayOf('N'.code.toByte(), 'V'.code.toByte(), 'A'.code.toByte(), 'B'.code.toByte())
        const val FORMAT_VERSION = 1
        private const val MAX_ENTRIES = 64
        private const val MAX_NAME_BYTES = 64

        fun encode(bindings: Map<ProductionGatewayId, String>): ByteArray {
            bindings.values.forEach { require(ManagedAwgKeyFingerprint.isWellFormed(it)) { "malformed fingerprint" } }
            val body = ByteArrayOutputStream().also { buffer ->
                DataOutputStream(buffer).use { out ->
                    out.write(MAGIC)
                    out.writeInt(FORMAT_VERSION)
                    out.writeInt(bindings.size)
                    bindings.entries.sortedBy { it.key.name }.forEach { (id, fingerprint) ->
                        val name = id.name.toByteArray(StandardCharsets.UTF_8)
                        out.writeShort(name.size)
                        out.write(name)
                        out.write(fingerprint.toByteArray(StandardCharsets.US_ASCII))
                    }
                }
            }.toByteArray()
            val crc = CRC32().apply { update(body) }.value
            return ByteArrayOutputStream().also { buffer ->
                DataOutputStream(buffer).use { out ->
                    out.write(body)
                    out.writeLong(crc)
                }
            }.toByteArray()
        }

        fun decode(bytes: ByteArray): ManagedAwgBindingLoadResult {
            if (bytes.size < MAGIC.size + 4 + 4 + 8) return ManagedAwgBindingLoadResult.Unreadable("truncated binding file")
            val body = bytes.copyOfRange(0, bytes.size - 8)
            val storedCrc = DataInputStream(bytes.inputStream(bytes.size - 8, 8)).readLong()
            if (!body.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) return ManagedAwgBindingLoadResult.Unreadable("bad magic")
            val input = DataInputStream(body.inputStream(MAGIC.size, body.size - MAGIC.size))
            return try {
                val version = input.readInt()
                if (version != FORMAT_VERSION) return ManagedAwgBindingLoadResult.Unreadable("unsupported binding format version $version")
                if (CRC32().apply { update(body) }.value != storedCrc) return ManagedAwgBindingLoadResult.Unreadable("bad checksum")
                val count = input.readInt()
                if (count !in 0..MAX_ENTRIES) return ManagedAwgBindingLoadResult.Unreadable("implausible entry count $count")
                val result = LinkedHashMap<ProductionGatewayId, String>()
                repeat(count) {
                    val nameLen = input.readUnsignedShort()
                    if (nameLen !in 1..MAX_NAME_BYTES) return ManagedAwgBindingLoadResult.Unreadable("malformed gateway id")
                    val name = ByteArray(nameLen).also { input.readFully(it) }.toString(StandardCharsets.UTF_8)
                    val id = ProductionGatewayId.entries.firstOrNull { it.name == name }
                        ?: return ManagedAwgBindingLoadResult.Unreadable("unknown gateway id")
                    val fingerprint = ByteArray(ManagedAwgKeyFingerprint.LENGTH).also { input.readFully(it) }
                        .toString(StandardCharsets.US_ASCII)
                    if (!ManagedAwgKeyFingerprint.isWellFormed(fingerprint)) return ManagedAwgBindingLoadResult.Unreadable("malformed fingerprint")
                    if (result.put(id, fingerprint) != null) return ManagedAwgBindingLoadResult.Unreadable("duplicate gateway id")
                }
                if (input.available() != 0) return ManagedAwgBindingLoadResult.Unreadable("trailing bytes")
                ManagedAwgBindingLoadResult.Valid(result)
            } catch (e: java.io.EOFException) {
                ManagedAwgBindingLoadResult.Unreadable("truncated binding file")
            } catch (e: IOException) {
                ManagedAwgBindingLoadResult.Unreadable("malformed binding file")
            }
        }
    }
}
