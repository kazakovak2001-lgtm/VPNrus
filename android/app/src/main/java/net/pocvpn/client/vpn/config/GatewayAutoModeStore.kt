package net.pocvpn.client.vpn.config

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B16 - device-local preference for whether Smart Connect should choose
 * AUTOMATICALLY between production gateways, or the user has pinned one
 * manually (see [SelectedGatewayStore], untouched by this store - it
 * remains the manual selection/fallback). Same "device-local, never
 * server-issued" discipline as SelectedGatewayStore's own docs. read()
 * NEVER throws and falls back to `false` (Manual) for a missing, corrupted,
 * or unrecognized file - preserving every pre-B16 install's behavior
 * byte-for-byte (manual gateway selection is the only mode that existed
 * before this slice).
 */
interface GatewayAutoModeStore {
    fun read(): Boolean
    fun write(auto: Boolean)

    companion object {
        /** Always reads Manual (false) and ignores writes - the safe default for call sites with no real persistence wired. */
        fun manualOnly(): GatewayAutoModeStore = object : GatewayAutoModeStore {
            override fun read() = false
            override fun write(auto: Boolean) = Unit
        }
    }
}

class FileGatewayAutoModeStore(
    private val directory: File,
    private val fileName: String = "gateway_auto_mode.txt",
) : GatewayAutoModeStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): Boolean {
        if (!file.exists()) return false
        return try {
            file.readText(Charsets.UTF_8).trim() == "AUTO"
        } catch (e: IOException) {
            false
        }
    }

    override fun write(auto: Boolean) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        tmp.writeText(if (auto) "AUTO" else "MANUAL", Charsets.UTF_8)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw IOException("failed to atomically replace gateway auto-mode file", e)
        }
    }
}
