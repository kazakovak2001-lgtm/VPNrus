package net.pocvpn.client.vpn.xray

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Decides, for the `:xray` process, which directory the Xray core gets as `xray.location.asset`
 * (via `Libv2ray.initCoreEnv`) and notices when the user activated a different dataset since.
 *
 * The core reads `geoip.dat` / `geosite.dat` only from that directory (device evidence: GEO-RUN
 * experiment, `root_control` failed with `failed to open geoip.dat` when the files were not directly in
 * the given directory). [GeoDataBootstrap] therefore always returns a directory that contains both files
 * at its top level.
 *
 * Nothing here hot-reloads a running core: [changedResolution] is meant to be asked only while the core is
 * stopped (before the next `startLoop`). The directory a running core was started with is never changed.
 */
class GeoAssetDirProvider(
    private val root: File,
    private val source: GeoAssetSource,
    private val log: (String) -> Unit = {},
) {
    private var lastSignature: String? = null
    private var last: GeoDataResolution? = null

    // A resolution is only a proposal until the caller reports (markApplied) that the core environment really
    // was pointed at it; until then nothing is committed and `.geo-effective` is not written.
    private var pending: GeoDataResolution? = null
    private var pendingSignature: String? = null

    /** First resolution of this process. Never throws. Call [markApplied] once `initCoreEnv` succeeded with it. */
    @Synchronized
    fun resolveInitial(): GeoDataResolution {
        val signature = GeoActiveDataset.pointerSignature(root)
        val resolution = GeoDataBootstrap.resolve(root, source, log)
        pending = resolution
        pendingSignature = signature
        return resolution
    }

    /**
     * The new resolution when the active-dataset pointer changed since the last applied one and it leads to a
     * different directory; otherwise null (cheap: one stat of the pointer file). Never throws. Call [markApplied]
     * after `initCoreEnv` succeeded with it; if that fails nothing is committed and the next start tries again.
     */
    @Synchronized
    fun changedResolution(): GeoDataResolution? {
        return try {
            val signature = GeoActiveDataset.pointerSignature(root)
            if (signature == lastSignature) return null
            val resolution = GeoDataBootstrap.resolve(root, source, log)
            if (resolution.directory == last?.directory) {
                lastSignature = signature
                return null
            }
            pending = resolution
            pendingSignature = signature
            resolution
        } catch (t: Throwable) {
            log("geo data: refresh failed (${t.javaClass.simpleName}); keeping previous directory")
            null
        }
    }

    /**
     * The core environment was successfully pointed at the last proposed resolution: commit it and record it in
     * `.geo-effective` (what Settings -> GeoData reports as "handed to the VPN core"). It states the directory
     * that was handed over, not that any database was read.
     */
    @Synchronized
    fun markApplied() {
        val resolution = pending ?: return
        last = resolution
        lastSignature = pendingSignature
        pending = null
        recordEffective(resolution)
    }

    /** Best effort and informational only; never affects the core start. */
    private fun recordEffective(resolution: GeoDataResolution) {
        try {
            val text = resolution.datasetId ?: ""
            val tmp = File(root, "$EFFECTIVE_NAME.tmp")
            FileOutputStream(tmp).use { it.write(text.toByteArray(Charsets.UTF_8)) }
            Files.move(tmp.toPath(), File(root, EFFECTIVE_NAME).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (t: Throwable) {
            // informational only
        }
    }

    companion object {
        const val EFFECTIVE_NAME = ".geo-effective"

        /** The dataset id the `:xray` process last successfully handed to the core environment, or null if unknown/none. */
        fun readEffectiveId(root: File): String? = try {
            File(root, EFFECTIVE_NAME).takeIf { it.isFile }?.readText(Charsets.UTF_8)?.trim()?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }
}
