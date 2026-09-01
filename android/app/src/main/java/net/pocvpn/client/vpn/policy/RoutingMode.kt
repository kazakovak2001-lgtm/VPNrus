package net.pocvpn.client.vpn.policy

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * B18 - the top-level, DEVICE-LOCAL user-facing routing mode. Orthogonal to
 * [AppRoutingPolicy] (see that file's own docs): [AppRoutingPolicy] decides
 * WHICH APPS' traffic reaches the VPN interface at all; [RoutingMode] decides
 * what happens, at the destination-route level, to traffic that DOES reach
 * it. Never server-issued, never comes from /v1/activate - same discipline
 * as [AppRoutingPolicy]/[net.pocvpn.client.vpn.config.GatewayAutoModeStore].
 *
 * FULL_VPN is the only safe default - it reproduces the exact pre-B18
 * full-tunnel route behavior, so existing installs/tests with no saved mode
 * (or a corrupted one) keep their current behavior unchanged. APPS is named
 * separately from FULL_VPN for UI clarity (the user is explicitly choosing
 * "route by app, not by destination") but is byte-for-byte IDENTICAL to
 * FULL_VPN at the destination-route layer - see RoutingDecisionEngine's own
 * docs for the exact precedence rule this preserves.
 */
enum class RoutingMode { FULL_VPN, ADAPTIVE, APPS }

interface RoutingModeStore {
    fun read(): RoutingMode
    fun write(mode: RoutingMode)

    companion object {
        /** Always reads FULL_VPN and ignores writes - the safe default for call sites with no real persistence wired (tests, additive constructor params). */
        fun fullVpn(): RoutingModeStore = object : RoutingModeStore {
            override fun read() = RoutingMode.FULL_VPN
            override fun write(mode: RoutingMode) = Unit
        }
    }
}

/**
 * A missing, corrupted, or unrecognized file falls back to [RoutingMode.FULL_VPN]
 * - fail-safe, matching every other device-local policy store in this
 * codebase (AppRoutingPolicyStore/GatewayAutoModeStore). Never throws.
 */
class FileRoutingModeStore(
    private val directory: File,
    private val fileName: String = "routing_mode.txt",
) : RoutingModeStore {

    private val file: File get() = File(directory, fileName)

    override fun read(): RoutingMode {
        if (!file.exists()) return RoutingMode.FULL_VPN
        return try {
            RoutingMode.entries.firstOrNull { it.name == file.readText(Charsets.UTF_8).trim() } ?: RoutingMode.FULL_VPN
        } catch (e: IOException) {
            RoutingMode.FULL_VPN
        }
    }

    override fun write(mode: RoutingMode) {
        directory.mkdirs()
        val tmp = File(directory, "$fileName.tmp")
        tmp.writeText(mode.name, Charsets.UTF_8)
        try {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: java.nio.file.FileSystemException) {
            tmp.delete()
            throw IOException("failed to atomically replace routing mode file", e)
        }
    }
}
