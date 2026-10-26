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

    /** First resolution of this process. Never throws. */
    @Synchronized
    fun resolveInitial(): GeoDataResolution {
        val signature = GeoActiveDataset.pointerSignature(root)
        val resolution = GeoDataBootstrap.resolve(root, source, log)
        lastSignature = signature
        last = resolution
        recordEffective(resolution)
        return resolution
    }

    /**
     * The new resolution when the active-dataset pointer changed since the last call and it leads to a
     * different directory; otherwise null (cheap: one stat of the pointer file). Never throws.
     */
    @Synchronized
    fun changedResolution(): GeoDataResolution? {
        return try {
            val signature = GeoActiveDataset.pointerSignature(root)
            if (signature == lastSignature) return null
            val resolution = GeoDataBootstrap.resolve(root, source, log)
            lastSignature = signature
            if (resolution.directory == last?.directory) return null
            last = resolution
            recordEffective(resolution)
            resolution
        } catch (t: Throwable) {
            log("geo data: refresh failed (${t.javaClass.simpleName}); keeping previous directory")
            null
        }
    }

    /**
     * Best effort: tells the main process (Settings -> GeoData) which dataset the core was last pointed at, so
     * the screen can say "in use" versus "will apply at the next connect". Never affects the core start.
     */
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

        /** The dataset id the `:xray` process last handed to the core, or null if unknown/none. */
        fun readEffectiveId(root: File): String? = try {
            File(root, EFFECTIVE_NAME).takeIf { it.isFile }?.readText(Charsets.UTF_8)?.trim()?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }
}
