package net.pocvpn.client.smartconnect

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import net.pocvpn.client.transport.TransportKind

/**
 * B8I - HISTORICAL connection outcomes, deliberately separate from
 * NetworkProfile (CURRENT network facts - see that class's own docs for why
 * these two are split). Strictly bounded (see [FileConnectionOutcomeStore]'s
 * maxRecords) - never an unbounded growing log.
 *
 * PRIVACY INVARIANT: only technical connection metadata may ever be
 * recorded here - see ConnectionOutcome's own field list. No IP address of
 * the user, no destination/browsing data, no DNS queries, no credentials or
 * key material. This store's file format has no field capable of holding
 * any of those - not merely a policy this store follows, but something the
 * format itself cannot represent.
 */
interface ConnectionOutcomeStore {
    fun recent(): List<ConnectionOutcome>
    fun record(outcome: ConnectionOutcome)
}

class FileConnectionOutcomeStore(
    private val directory: File,
    private val fileName: String = "connection_outcomes.bin",
    private val maxRecords: Int = 30,
) : ConnectionOutcomeStore {

    private val file: File get() = File(directory, fileName)
    private val lock = Any()

    @Volatile private var cached: List<ConnectionOutcome> = readFromDisk()

    override fun recent(): List<ConnectionOutcome> = cached

    override fun record(outcome: ConnectionOutcome) {
        synchronized(lock) {
            // takeLast enforces the bound unconditionally - even if maxRecords
            // were somehow reduced between runs, this never re-grows past it.
            val updated = (cached + outcome).takeLast(maxRecords)
            cached = updated
            writeToDisk(updated)
        }
    }

    private fun readFromDisk(): List<ConnectionOutcome> {
        if (!file.exists()) return emptyList()
        return try {
            DataInputStream(file.inputStream().buffered()).use { input ->
                val version = input.readInt()
                if (version != FORMAT_VERSION) return emptyList()
                val count = input.readInt()
                if (count !in 0..MAX_PLAUSIBLE_COUNT) return emptyList()
                (0 until count).mapNotNull { readOutcomeOrNull(input) }.takeLast(maxRecords)
            }
        } catch (e: java.io.IOException) {
            emptyList()
        } catch (e: IllegalArgumentException) {
            emptyList()
        }
    }

    private fun readOutcomeOrNull(input: DataInputStream): ConnectionOutcome? {
        val transportOrdinal = input.readInt()
        val transport = TransportKind.entries.getOrNull(transportOrdinal) ?: return null
        val gatewayId = readString(input)
        val resultOrdinal = input.readInt()
        val result = ConnectionOutcomeResult.entries.getOrNull(resultOrdinal) ?: return null
        val hasDuration = input.readBoolean()
        val duration = input.readLong()
        val errorOrdinal = input.readInt()
        val errorCategory = ConnectionErrorCategory.entries.getOrNull(errorOrdinal) ?: return null
        val timestamp = input.readLong()
        return ConnectionOutcome(
            transport = transport,
            gatewayId = gatewayId,
            result = result,
            handshakeDurationMs = if (hasDuration) duration else null,
            errorCategory = errorCategory,
            timestampEpochMillis = timestamp,
        )
    }

    private fun writeToDisk(outcomes: List<ConnectionOutcome>) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        val bytes = ByteArrayOutputStream().also { buffer ->
            DataOutputStream(buffer).use { out ->
                out.writeInt(FORMAT_VERSION)
                out.writeInt(outcomes.size)
                outcomes.forEach { outcome ->
                    out.writeInt(outcome.transport.ordinal)
                    writeString(out, outcome.gatewayId)
                    out.writeInt(outcome.result.ordinal)
                    out.writeBoolean(outcome.handshakeDurationMs != null)
                    out.writeLong(outcome.handshakeDurationMs ?: 0L)
                    out.writeInt(outcome.errorCategory.ordinal)
                    out.writeLong(outcome.timestampEpochMillis)
                }
            }
        }.toByteArray()
        tmp.writeBytes(bytes)
        // record() legitimately overwrites an already-existing file on
        // EVERY call after the first (unlike the other B8-series stores,
        // which each write at most once per app lifecycle event) - plain
        // File.renameTo() is unspecified/platform-dependent for that exact
        // case (fails to replace an existing destination on Windows,
        // succeeds via POSIX rename() on Android/Linux). Files.move with
        // REPLACE_EXISTING is the portable, still-atomic-on-POSIX way to
        // get the same guarantee on every platform this can run on.
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace connection outcome file", e)
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
        const val FORMAT_VERSION = 1
        const val MAX_STRING_LEN = 256
        const val MAX_PLAUSIBLE_COUNT = 4096
    }
}
