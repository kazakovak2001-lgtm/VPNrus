package net.pocvpn.client.vpn.config

import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B22 - the explicit, single, three-way gateway-selection authority
 * (architecture constraint 2): which of the three DISJOINT gateway sources
 * is authoritative for the next connect() attempt.
 *
 * - [AUTO] -> the existing trusted-manifest/AutoGatewaySelector path
 *   (unchanged - see PROJECT_ARCHITECTURE.md's B16/B17 sections).
 * - [MANUAL_MANAGED] -> the existing ProductionGatewayCatalog/
 *   SelectedGatewayStore manual path (unchanged).
 * - [PRIVATE] -> [PrivateGatewayStore] only - never
 *   ProductionGatewayCatalog, never signed manifest data (see
 *   PrivateGatewayConfig's own docs for why a private gateway is
 *   structurally incapable of entering either).
 *
 * This is a NEW, additive authority - it does not replace
 * [GatewayAutoModeStore]'s existing boolean (still read by
 * AutoGatewaySelector-adjacent code paths this slice does not touch);
 * MainViewModel keeps that boolean in lockstep (true only when this mode is
 * [AUTO]) so nothing reading the old boolean observes a behavior change.
 */
enum class GatewaySelectionMode {
    AUTO,
    MANUAL_MANAGED,
    PRIVATE,
}

/**
 * Device-local persisted selection of [GatewaySelectionMode]. Same
 * "device-local preference, never server-issued" reasoning as
 * [SelectedGatewayStore]/[GatewayAutoModeStore] (see their own docs).
 * read() NEVER throws and falls back to [GatewaySelectionMode.MANUAL_MANAGED]
 * for a missing, corrupted, or unrecognized file - preserving today's actual
 * default behavior (gatewayAutoModeStore.read() defaults to Manual) for
 * every install that predates this store.
 */
interface GatewaySelectionModeStore {
    fun read(): GatewaySelectionMode
    fun write(mode: GatewaySelectionMode)

    companion object {
        /** Always reads MANUAL_MANAGED and ignores writes - the safe default for call sites with no real persistence wired. */
        fun managedOnly(): GatewaySelectionModeStore = object : GatewaySelectionModeStore {
            override fun read() = GatewaySelectionMode.MANUAL_MANAGED
            override fun write(mode: GatewaySelectionMode) = Unit
        }
    }
}

class FileGatewaySelectionModeStore(
    private val directory: File,
    private val fileName: String = "gateway_selection_mode.txt",
) : GatewaySelectionModeStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): GatewaySelectionMode {
        if (!file.exists()) return GatewaySelectionMode.MANUAL_MANAGED
        return try {
            val name = file.readText(Charsets.UTF_8).trim()
            GatewaySelectionMode.entries.firstOrNull { it.name == name } ?: GatewaySelectionMode.MANUAL_MANAGED
        } catch (e: java.io.IOException) {
            GatewaySelectionMode.MANUAL_MANAGED
        }
    }

    override fun write(mode: GatewaySelectionMode) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        tmp.writeText(mode.name, Charsets.UTF_8)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw java.io.IOException("failed to atomically replace gateway selection mode file", e)
        }
    }
}
