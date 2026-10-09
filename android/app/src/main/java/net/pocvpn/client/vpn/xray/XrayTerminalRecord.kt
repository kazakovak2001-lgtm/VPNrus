package net.pocvpn.client.vpn.xray

import android.content.Context
import java.io.File

/**
 * The last terminal event (Stopped/Failed) the `:xray` service published,
 * written synchronously BEFORE its broadcast and before stopSelf(). When
 * the main process learns of a `:xray` death before that broadcast lands,
 * it reads this file instead of guessing: a deliberate Stopped (explicit
 * stop, VPN revoked by the system) stays Stopped and a typed Failed (e.g.
 * the relay watchdog's RELAY_DATA_PLANE_LOST) keeps its failureKind. No
 * record for the dying session means a real crash.
 *
 * Same non-secret fields the broadcast already carries (type, session id,
 * failure kind, short reason); one small app-private file in
 * noBackupFilesDir, replaced atomically. Unreadable/malformed = no record.
 */
internal class XrayTerminalRecord(private val file: File) {

    fun write(event: XrayRuntimeEvent) {
        if (event is XrayRuntimeEvent.Started) return
        val e = XrayProcessBridge.encode(event)
        val text = listOf(e.type, e.sessionId.toString(), e.failureKind.orEmpty(), (e.reason ?: "").replace('\n', ' ').take(MAX_REASON))
            .joinToString("\n")
        try {
            file.parentFile?.mkdirs()
            val tmp = File(file.parentFile, file.name + ".tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(file)) {
                file.delete()
                tmp.renameTo(file)
            }
        } catch (e: Exception) {
            // Best effort: without a record the main process reports a generic Failed (fail-closed).
        }
    }

    fun read(): XrayRuntimeEvent? = try {
        val lines = file.readText().split('\n')
        if (lines.size != 4) {
            null
        } else {
            val sessionId = lines[1].toLongOrNull()
            if (sessionId == null) {
                null
            } else {
                XrayProcessBridge.decode(
                    XrayProcessBridge.Encoded(lines[0], sessionId, lines[3].ifEmpty { null }, lines[2].ifEmpty { null }),
                )?.takeIf { it !is XrayRuntimeEvent.Started }
            }
        }
    } catch (e: Exception) {
        null
    }

    companion object {
        private const val MAX_REASON = 200

        fun forContext(context: Context): XrayTerminalRecord =
            XrayTerminalRecord(File(context.noBackupFilesDir, "xray-terminal-event"))
    }
}
