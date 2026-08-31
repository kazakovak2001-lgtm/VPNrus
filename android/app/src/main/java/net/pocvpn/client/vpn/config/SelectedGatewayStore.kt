package net.pocvpn.client.vpn.config

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B13 - the one canonical, DEVICE-LOCAL store for which production gateway
 * the user has manually selected. Same "device-local preference, never
 * server-issued" reasoning as AppRoutingPolicyStore (see its own docs) - a
 * gateway choice is not something /v1/activate returns or should ever write
 * back to. read() NEVER throws and falls back to
 * [ProductionGatewayId.GERMANY] (preserving every pre-B13 single-gateway
 * default) for a missing, corrupted, or unrecognized file - fail-safe, same
 * discipline as AppRoutingPolicyStore's own "no saved policy -> Default".
 */
interface SelectedGatewayStore {
    fun read(): ProductionGatewayId
    fun write(id: ProductionGatewayId)

    companion object {
        /** Always reads GERMANY and ignores writes - the safe default for call sites with no real persistence wired. */
        fun germanyOnly(): SelectedGatewayStore = object : SelectedGatewayStore {
            override fun read() = ProductionGatewayId.GERMANY
            override fun write(id: ProductionGatewayId) = Unit
        }
    }
}

class FileSelectedGatewayStore(
    private val directory: File,
    private val fileName: String = "selected_gateway.txt",
) : SelectedGatewayStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): ProductionGatewayId {
        if (!file.exists()) return ProductionGatewayId.GERMANY
        return try {
            val name = file.readText(Charsets.UTF_8).trim()
            ProductionGatewayId.entries.firstOrNull { it.name == name } ?: ProductionGatewayId.GERMANY
        } catch (e: java.io.IOException) {
            ProductionGatewayId.GERMANY
        }
    }

    override fun write(id: ProductionGatewayId) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        tmp.writeText(id.name, Charsets.UTF_8)
        // Files.move(..., REPLACE_EXISTING) rather than File.renameTo() -
        // renameTo() does NOT overwrite an existing destination on Windows
        // (same fix FilePathHistoryStore's own writeToDisk already applies),
        // and a selection changes an EXISTING file on every write after the
        // first.
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace selected gateway file", e)
        }
    }
}
