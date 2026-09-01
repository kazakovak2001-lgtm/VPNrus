package net.pocvpn.client.reachability

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import net.pocvpn.client.transport.TransportKind

/**
 * Aggregated local history for one (networkFingerprint, endpointId, transportKind) key - never raw per-attempt destinations/timestamps beyond what's needed to bound recency.
 *
 * B19 - [consecutiveFailures] is the RECENT streak (resets to 0 on any
 * success, increments on each failure) - deliberately distinct from
 * [failureCount] (a lifetime cumulative total that never decreases). This is
 * what [net.pocvpn.client.reachability.PathScorer]'s bounded cooldown
 * penalty is keyed on: a streak naturally clears on the next success and the
 * penalty itself additionally decays with time (see that object's own
 * docs) - never a permanent blacklist. Defaults to 0 so every pre-B19
 * construction (every existing test/call site) is byte-for-byte unaffected.
 */
data class PathHistoryEntry(
    val successCount: Int,
    val failureCount: Int,
    val lastOutcomeEpochMillis: Long,
    val lastOutcomeSuccess: Boolean,
    val consecutiveFailures: Int = 0,
)

/**
 * B11 - network-specific local connection memory, keyed by
 * (networkFingerprint x endpointId x transportKind) exactly as the task
 * specifies. [networkFingerprint] must already be the HMAC output of
 * NetworkFingerprinter - this store has no way to enforce that itself, but
 * it structurally CANNOT hold raw SSID/BSSID/IMSI/DNS data because its
 * key/value shape has no field for them (same "the format itself cannot
 * represent it" discipline as ConnectionOutcomeStore).
 */
interface PathHistoryStore {
    fun get(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind): PathHistoryEntry?
    fun record(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind, success: Boolean, nowEpochMillis: Long)
}

/**
 * File-backed, bounded (see [maxEntries]) local store. Eviction is
 * least-recently-updated first once the bound is hit - a device that visits
 * many networks over time never grows this file without limit.
 */
class FilePathHistoryStore(
    private val directory: File,
    private val fileName: String = "path_history.bin",
    private val maxEntries: Int = 200,
) : PathHistoryStore {

    private data class Key(val fingerprint: String, val endpointId: String, val transportOrdinal: Int)

    private val file: File get() = File(directory, fileName)
    private val lock = Any()

    @Volatile private var cached: LinkedHashMap<Key, PathHistoryEntry> = readFromDisk()

    override fun get(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind): PathHistoryEntry? =
        cached[Key(networkFingerprint, endpointId.value, transport.ordinal)]

    override fun record(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {
        synchronized(lock) {
            val key = Key(networkFingerprint, endpointId.value, transport.ordinal)
            val existing = cached[key]
            val updated = PathHistoryEntry(
                successCount = (existing?.successCount ?: 0) + if (success) 1 else 0,
                failureCount = (existing?.failureCount ?: 0) + if (success) 0 else 1,
                lastOutcomeEpochMillis = nowEpochMillis,
                lastOutcomeSuccess = success,
                // B19 - the RECENT streak: cleared by any success, otherwise incremented.
                consecutiveFailures = if (success) 0 else (existing?.consecutiveFailures ?: 0) + 1,
            )
            // Copy-on-write, not an in-place mutation of the shared `cached`
            // map: [get] deliberately reads `cached` without taking [lock]
            // (same safe-publication pattern as FileLastKnownGoodManifestStore's
            // `current()`), which is only safe when the referenced object
            // itself is never mutated after being made visible - mutating
            // the SAME LinkedHashMap instance a concurrent unsynchronized
            // get() might be iterating/reading was a real data race
            // (ConcurrentModificationException / corrupted map internals).
            // Rebuilding a new map and reassigning the @Volatile reference
            // keeps every previously-published snapshot immutable.
            val newCache = LinkedHashMap(cached)
            newCache.remove(key)
            newCache[key] = updated
            while (newCache.size > maxEntries) {
                val oldestKey = newCache.keys.firstOrNull() ?: break
                newCache.remove(oldestKey)
            }
            writeToDisk(newCache)
            cached = newCache
        }
    }

    private fun readFromDisk(): LinkedHashMap<Key, PathHistoryEntry> {
        if (!file.exists()) return LinkedHashMap()
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) return LinkedHashMap()
                val count = input.readInt()
                if (count !in 0..MAX_PLAUSIBLE_COUNT) return LinkedHashMap()
                val map = LinkedHashMap<Key, PathHistoryEntry>()
                repeat(count) {
                    val entry = readEntryOrNull(input) ?: return LinkedHashMap()
                    map[entry.first] = entry.second
                }
                map
            }
        } catch (e: java.io.IOException) {
            LinkedHashMap()
        } catch (e: IllegalArgumentException) {
            LinkedHashMap()
        }
    }

    private fun readEntryOrNull(input: DataInputStream): Pair<Key, PathHistoryEntry>? {
        val fingerprint = readString(input)
        val endpointId = readString(input)
        val transportOrdinal = input.readInt()
        if (TransportKind.entries.getOrNull(transportOrdinal) == null) return null
        val successCount = input.readInt()
        val failureCount = input.readInt()
        val lastOutcomeEpochMillis = input.readLong()
        val lastOutcomeSuccess = input.readBoolean()
        val consecutiveFailures = input.readInt()
        return Key(fingerprint, endpointId, transportOrdinal) to
            PathHistoryEntry(successCount, failureCount, lastOutcomeEpochMillis, lastOutcomeSuccess, consecutiveFailures)
    }

    private fun writeToDisk(entries: Map<Key, PathHistoryEntry>) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                out.writeInt(entries.size)
                entries.forEach { (key, entry) ->
                    writeString(out, key.fingerprint)
                    writeString(out, key.endpointId)
                    out.writeInt(key.transportOrdinal)
                    out.writeInt(entry.successCount)
                    out.writeInt(entry.failureCount)
                    out.writeLong(entry.lastOutcomeEpochMillis)
                    out.writeBoolean(entry.lastOutcomeSuccess)
                    out.writeInt(entry.consecutiveFailures)
                }
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace path history file", e)
        }
    }

    private fun writeString(out: DataOutputStream, s: String) {
        val bytes = s.toByteArray(StandardCharsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }

    private fun readString(input: DataInputStream): String {
        val len = input.readInt()
        require(len in 0..MAX_STRING_LEN) { "implausible length-prefixed field: $len" }
        val bytes = ByteArray(len)
        input.readFully(bytes)
        return String(bytes, StandardCharsets.UTF_8)
    }

    private companion object {
        // B19 - bumped 1 -> 2 to add consecutiveFailures. A pre-B19 file
        // fails the version check below and falls back to an empty map
        // (the SAME fail-safe "unrecognized format -> start clean" every
        // other store here already uses) - never a crash, never a
        // misread field.
        const val FORMAT_VERSION = 2
        const val MAX_STRING_LEN = 256
        const val MAX_PLAUSIBLE_COUNT = 100_000
    }
}
