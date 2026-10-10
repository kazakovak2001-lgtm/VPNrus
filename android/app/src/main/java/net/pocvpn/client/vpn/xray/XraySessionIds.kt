package net.pocvpn.client.vpn.xray

import android.content.Context
import java.io.File

/**
 * Xray session ids for the main process. The main mirror and the death
 * watch rely on ids only growing ([XrayProcessBridge.acceptInMain],
 * [XrayProcessWatcher.onEvent]), and a `:xray` process can outlive a
 * main-process restart and keep publishing for an older session.
 *
 * Wall-clock seeding alone breaks after the clock moves back between two
 * main-process runs. Instead every id handed out is first covered by a
 * persisted ceiling ([persistCeiling], reserved [reserve] ids at a time), and
 * a new run starts above max(stored ceiling, [clock], [floor]). Guarantee:
 * ids strictly increase within a run, and across runs whenever the ceiling
 * write succeeded; if it fails, the next allocation retries it and the run
 * falls back to the wall-clock seed for later runs.
 */
internal class XraySessionIdAllocator(
    private val readCeiling: () -> Long?,
    private val persistCeiling: (Long) -> Boolean,
    private val clock: () -> Long = System::currentTimeMillis,
    private val reserve: Long = RESERVE,
    private val floor: Long = 0L,
) {
    private var last: Long? = null
    private var ceiling = Long.MIN_VALUE

    @Synchronized
    fun nextId(): Long {
        val previous = last ?: maxOf(readCeiling() ?: 0L, clock(), floor)
        val id = previous + 1
        if (id > ceiling) {
            val reserved = id + reserve
            if (persistCeiling(reserved)) ceiling = reserved
        }
        last = id
        return id
    }

    /** The newest id handed out, or [floor] before the first one. */
    @Synchronized
    fun lastIssued(): Long = last ?: floor

    companion object {
        const val RESERVE = 1_000L
    }
}

/**
 * The persisted ceiling for [XraySessionIdAllocator]: one decimal line in
 * app-private no-backup storage, replaced through a uniquely named temp file
 * and an atomic move (same discipline as [XrayTerminalRecord]). A missing,
 * malformed or negative value reads as null (no ceiling).
 */
internal class XraySessionIdCeilingFile(private val file: File) {

    fun read(): Long? = try {
        file.readText().trim().toLongOrNull()?.takeIf { it >= 0 }
    } catch (e: Exception) {
        null
    }

    @Synchronized
    fun write(ceiling: Long): Boolean {
        var tmp: File? = null
        return try {
            val dir = file.parentFile ?: return false
            dir.mkdirs()
            tmp = File.createTempFile(file.name + ".", ".tmp", dir)
            tmp.writeText(ceiling.toString())
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
        fun forContext(context: Context): XraySessionIdCeilingFile =
            XraySessionIdCeilingFile(File(context.noBackupFilesDir, "xray-session-id-ceiling"))
    }
}
