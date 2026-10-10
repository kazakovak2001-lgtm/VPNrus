package net.pocvpn.client.vpn.xray

import android.content.Context
import java.io.File

/**
 * The last terminal event (Stopped/Failed) of the session the `:xray`
 * service currently owns, as one small app-private file the MAIN process
 * reads when it learns of a `:xray` death before the event's broadcast
 * lands: a deliberate Stopped (explicit stop, VPN revoked by the system)
 * stays Stopped and a typed Failed (e.g. the relay watchdog's
 * RELAY_DATA_PLANE_LOST) keeps its failureKind. No record for the dying
 * session means a real crash.
 *
 * File format: four lines (type, session id, failure kind, short reason) -
 * the same non-secret fields the broadcast already carries. Every change
 * goes to a fresh, uniquely named temp file in the same directory and is
 * then moved over the record with ATOMIC_MOVE (rename(2) on Android,
 * which replaces atomically), so a
 * reader in either process sees the previous complete record, the new
 * complete record, or none - never a partial or mixed one. [lock] orders
 * this process' writers. Anything unreadable/malformed/unknown is "no
 * record", which the main process treats as a crash (generic Failed).
 *
 * Policy (which session may be recorded, when to clear) lives in
 * [XrayTerminalJournal]; this class only stores and reads.
 */
internal class XrayTerminalRecord(private val file: File) {

    private val lock = Any()

    /** Atomically replaces the record with [event] (Started is never stored). False when the write did not land. */
    fun write(event: XrayRuntimeEvent): Boolean {
        if (event is XrayRuntimeEvent.Started) return false
        val e = XrayProcessBridge.encode(event)
        val text = listOf(e.type, e.sessionId.toString(), e.failureKind.orEmpty(), (e.reason ?: "").replace('\n', ' ').take(MAX_REASON))
            .joinToString("\n")
        return replaceWith(text)
    }

    /**
     * Removes the record. When the file cannot be deleted, an unreadable
     * tombstone takes its place so a stale record can never be read back.
     */
    fun clear(): Boolean = synchronized(lock) {
        if (!file.exists() || file.delete()) true else replaceWith(TOMBSTONE)
    }

    fun read(): XrayRuntimeEvent? = try {
        val lines = file.readText().split('\n')
        val sessionId = lines.getOrNull(1)?.toLongOrNull()
        if (lines.size != 4 || sessionId == null) {
            null
        } else {
            XrayProcessBridge.decode(
                XrayProcessBridge.Encoded(lines[0], sessionId, lines[3].ifEmpty { null }, lines[2].ifEmpty { null }),
            )?.takeIf { it !is XrayRuntimeEvent.Started }
        }
    } catch (e: Exception) {
        null
    }

    private fun replaceWith(text: String): Boolean = synchronized(lock) {
        var tmp: File? = null
        try {
            val dir = file.parentFile ?: return false
            dir.mkdirs()
            tmp = File.createTempFile(file.name + ".", ".tmp", dir)
            tmp.writeText(text)
            // ATOMIC_MOVE + REPLACE_EXISTING: rename(2) on Android, which
            // atomically replaces the old record; an exception (including
            // AtomicMoveNotSupportedException) means "not written".
            java.nio.file.Files.move(
                tmp.toPath(),
                file.toPath(),
                java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING,
            )
            true
        } catch (e: Exception) {
            tmp?.delete()
            false
        }
    }

    companion object {
        private const val MAX_REASON = 200

        /** Not a known event type: [read] returns null for it. */
        private const val TOMBSTONE = "cleared\n0\n\n"

        fun forContext(context: Context): XrayTerminalRecord =
            XrayTerminalRecord(File(context.noBackupFilesDir, "xray-terminal-event"))
    }
}

/**
 * `:xray`-side policy for [XrayTerminalRecord], one instance per process.
 * [onPublish] runs, under [lock], immediately before the event's broadcast
 * is sent (see [XrayProcessBridge.publishFromService]), so record order and
 * broadcast order are the same.
 *
 * - Started(S): S becomes the owned session and any older record is
 *   cleared - a record left by a previous session, process or app run can
 *   never be read for S (no reliance on session-id ordering or clocks).
 * - A terminal event is recorded only for the owned session (equality, not
 *   ordering), and only the FIRST one per session: the main mirror also
 *   accepts only the first terminal broadcast, and a late event of an older
 *   session can neither replace nor erase the current session's record.
 */
internal class XrayTerminalJournal(private val record: XrayTerminalRecord) {

    val lock = Any()
    private var ownedSession: Long? = null
    private var recordedSession: Long? = null

    /** Caller holds [lock]. Returns true when [event] was written to the record. */
    fun onPublish(event: XrayRuntimeEvent): Boolean {
        check(Thread.holdsLock(lock)) { "onPublish must run under XrayTerminalJournal.lock" }
        return when (event) {
            is XrayRuntimeEvent.Started -> {
                ownedSession = event.sessionId
                recordedSession = null
                record.clear()
                false
            }
            is XrayRuntimeEvent.Stopped, is XrayRuntimeEvent.Failed -> {
                if (event.sessionId != ownedSession || recordedSession == event.sessionId) {
                    false
                } else {
                    record.write(event).also { written -> if (written) recordedSession = event.sessionId }
                }
            }
        }
    }
}
