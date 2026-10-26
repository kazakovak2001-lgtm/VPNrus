package net.pocvpn.client.geodata

import net.pocvpn.client.vpn.xray.GeoActivePointer
import net.pocvpn.client.vpn.xray.GeoActiveDataset
import net.pocvpn.client.vpn.xray.GeoAssetDirProvider
import net.pocvpn.client.vpn.xray.GeoAssetSource
import net.pocvpn.client.vpn.xray.GeoDataOrigin
import net.pocvpn.client.vpn.xray.GeoDataStager
import net.pocvpn.client.vpn.xray.GeoDataStagingResult
import net.pocvpn.client.vpn.xray.GeoFileInfo
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.StandardOpenOption

enum class GeoUpdatePhase { DOWNLOADING, STAGING, ACTIVATING }

data class GeoProgress(
    val phase: GeoUpdatePhase,
    val file: GeoDatabaseKind?,
    val bytesDone: Long = 0L,
    /** -1 when the server did not announce a size. */
    val bytesTotal: Long = -1L,
)

enum class GeoUpdateFailureKind {
    NOT_CONFIGURED,
    INVALID_URL,
    DOWNLOAD_FAILED,
    BUSY,
    STAGING_FAILED,
    ACTIVATION_FAILED,
    CANCELLED,
}

sealed class GeoUpdateResult {
    /** A new pair was downloaded, validated, published and activated. [changed] are the files that came from the network. */
    data class Updated(val datasetId: String, val changed: List<GeoDatabaseKind>, val files: List<GeoFileInfo>) : GeoUpdateResult()

    /** Everything downloaded was byte-identical to what is already active; nothing was changed. */
    data class AlreadyCurrent(val datasetId: String) : GeoUpdateResult()

    data class Failed(
        val kind: GeoUpdateFailureKind,
        val file: GeoDatabaseKind? = null,
        val download: GeoDownloadFailure? = null,
        val httpStatus: Int? = null,
        val invalidReason: GeoInvalidReason? = null,
        val detail: String = "",
    ) : GeoUpdateResult()
}

/** What the screen shows: which databases are in use and, for a downloaded pair, when it was activated. */
data class GeoDataStatus(
    val origin: GeoDataOrigin,
    val datasetId: String?,
    val files: List<GeoFileInfo>,
    val activatedAtMillis: Long?,
    /** A pointer exists but the dataset it names is missing or damaged (the bundled databases are used instead). */
    val activePointerBroken: Boolean,
    /** The dataset id the VPN core process last started with, if known. */
    val coreDatasetId: String?,
)

/**
 * Downloads new `geoip.dat` / `geosite.dat`, validates them and activates them as one dataset - or leaves
 * everything as it was.
 *
 * Safety properties (each is covered by a unit test):
 * - Nothing in use is ever written: downloads go to a temp directory, the new pair is published as a new
 *   content-addressed `geo-<id>` directory by [GeoDataStager], and only then does the pointer flip (atomic rename).
 *   Any failure before the flip leaves the pointer, and so the currently active databases, unchanged.
 * - Both files of an update are validated before either is activated. With only one URL configured the other
 *   file is carried over from the currently active dataset (or the bundled one), so the activated pair is always complete.
 * - Concurrent updates (also from another process) are refused via a lock file; they cannot interleave.
 * - The previously active dataset is kept on disk and, like the dataset a running core was started with, never
 *   pruned; only older downloaded datasets are removed. There is NO automatic rollback to it: if the active
 *   dataset is ever unusable the fallback is the bundled databases (the pointer's `previous` is bookkeeping for pruning).
 */
class GeoDataUpdater(
    private val root: File,
    private val bundledSource: GeoAssetSource,
    private val downloader: GeoDatabaseDownloader,
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {

    fun update(
        settings: GeoDataSettings,
        isCancelled: () -> Boolean = { false },
        onProgress: (GeoProgress) -> Unit = {},
    ): GeoUpdateResult {
        val urls = LinkedHashMap<GeoDatabaseKind, String>()
        for (kind in GeoDatabaseKind.entries) {
            when (val v = GeoUrlValidator.validate(settings.urlFor(kind))) {
                is GeoUrlValidation.Empty -> Unit
                is GeoUrlValidation.Valid -> urls[kind] = v.url
                is GeoUrlValidation.Invalid -> return GeoUpdateResult.Failed(GeoUpdateFailureKind.INVALID_URL, file = kind)
            }
        }
        if (urls.isEmpty()) return GeoUpdateResult.Failed(GeoUpdateFailureKind.NOT_CONFIGURED)

        if (!root.isDirectory && !root.mkdirs()) {
            return GeoUpdateResult.Failed(GeoUpdateFailureKind.STAGING_FAILED, detail = "Storage is not available.")
        }
        val channel = try {
            FileChannel.open(File(root, LOCK_NAME).toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (e: IOException) {
            return GeoUpdateResult.Failed(GeoUpdateFailureKind.STAGING_FAILED, detail = "Storage is not available.")
        }
        val lock = try {
            channel.tryLock()
        } catch (e: OverlappingFileLockException) {
            null
        } catch (e: IOException) {
            null
        }
        if (lock == null) {
            channel.close()
            return GeoUpdateResult.Failed(GeoUpdateFailureKind.BUSY)
        }
        val tempDir = File(root, TEMP_NAME)
        try {
            return run(urls, tempDir, isCancelled, onProgress)
        } finally {
            clearTemp(tempDir)
            try { lock.release() } catch (ignored: IOException) { }
            try { channel.close() } catch (ignored: IOException) { }
        }
    }

    private fun run(
        urls: Map<GeoDatabaseKind, String>,
        tempDir: File,
        isCancelled: () -> Boolean,
        onProgress: (GeoProgress) -> Unit,
    ): GeoUpdateResult {
        if (!prepareTemp(tempDir)) {
            return GeoUpdateResult.Failed(GeoUpdateFailureKind.STAGING_FAILED, detail = "The temporary download area is not usable.")
        }
        val current = GeoActiveDataset.resolveVerified(root)

        val downloaded = LinkedHashMap<GeoDatabaseKind, File>()
        for ((kind, url) in urls) {
            if (isCancelled()) return GeoUpdateResult.Failed(GeoUpdateFailureKind.CANCELLED)
            val dest = File(tempDir, kind.fileName + ".download")
            onProgress(GeoProgress(GeoUpdatePhase.DOWNLOADING, kind))
            val result = downloader.download(url, kind, dest, isCancelled) { done, total ->
                onProgress(GeoProgress(GeoUpdatePhase.DOWNLOADING, kind, done, total))
            }
            when (result) {
                is GeoDownloadResult.Success -> downloaded[kind] = result.file
                is GeoDownloadResult.Failure -> {
                    return if (result.kind == GeoDownloadFailure.CANCELLED) {
                        GeoUpdateResult.Failed(GeoUpdateFailureKind.CANCELLED, kind)
                    } else {
                        GeoUpdateResult.Failed(
                            GeoUpdateFailureKind.DOWNLOAD_FAILED,
                            file = kind,
                            download = result.kind,
                            httpStatus = result.httpStatus,
                            invalidReason = result.invalidReason,
                            detail = result.detail,
                        )
                    }
                }
            }
        }
        if (isCancelled()) return GeoUpdateResult.Failed(GeoUpdateFailureKind.CANCELLED)

        // Every file of the new pair: freshly downloaded, or carried over unchanged.
        val composite = GeoAssetSource { name ->
            val kind = GeoDatabaseKind.entries.first { it.fileName == name }
            val fresh = downloaded[kind]
            when {
                fresh != null -> FileInputStream(fresh)
                current != null -> FileInputStream(File(current.directory, name))
                else -> bundledSource.open(name)
            }
        }
        onProgress(GeoProgress(GeoUpdatePhase.STAGING, null))
        val staged = GeoDataStager(root, composite, markerSource = GeoDataStager.SOURCE_DOWNLOADED).ensureDataset()
        val ready = when (staged) {
            is GeoDataStagingResult.Ready -> staged
            is GeoDataStagingResult.Failed ->
                return GeoUpdateResult.Failed(GeoUpdateFailureKind.STAGING_FAILED, detail = "The new databases could not be prepared (${staged.kind}).")
        }
        if (isCancelled()) return GeoUpdateResult.Failed(GeoUpdateFailureKind.CANCELLED)

        if (current != null && current.datasetId == ready.datasetId) {
            return GeoUpdateResult.AlreadyCurrent(ready.datasetId)
        }

        onProgress(GeoProgress(GeoUpdatePhase.ACTIVATING, null))
        val pointer = GeoActivePointer(ready.datasetId, current?.datasetId, nowMillis())
        try {
            GeoActiveDataset.writePointer(root, pointer)
        } catch (e: IOException) {
            return GeoUpdateResult.Failed(GeoUpdateFailureKind.ACTIVATION_FAILED, detail = "The new databases could not be activated; the currently active ones are unchanged.")
        }
        // Also keep the dataset the running VPN core was started with: two quick updates must not remove the
        // directory a still-running core was pointed at.
        GeoActiveDataset.prune(root, setOfNotNull(ready.datasetId, current?.datasetId, GeoAssetDirProvider.readEffectiveId(root)))
        return GeoUpdateResult.Updated(ready.datasetId, downloaded.keys.toList(), ready.files)
    }

    /**
     * Stops using downloaded databases and returns to the bundled ones. Only the pointer is removed; the
     * previously active dataset stays on disk (a running core may still read it) until the next update prunes it.
     * Returns false when the pointer could not be removed (nothing changed then).
     */
    fun resetToBundled(): Boolean {
        val old = GeoActiveDataset.readPointer(root)
        if (!GeoActiveDataset.clearPointer(root)) return false
        GeoActiveDataset.prune(root, setOfNotNull(old?.active, GeoAssetDirProvider.readEffectiveId(root)))
        return true
    }

    /** Reads what is in use for the screen. Hashes files, so call it off the main thread. */
    fun status(): GeoDataStatus {
        val pointer = GeoActiveDataset.readPointer(root)
        val active = GeoActiveDataset.resolveVerified(root)
        val coreId = GeoAssetDirProvider.readEffectiveId(root)
        if (active != null) {
            return GeoDataStatus(GeoDataOrigin.DOWNLOADED, active.datasetId, active.files, pointer?.activatedAtMillis, false, coreId)
        }
        val bundled = try {
            DATABASE_NAMES.map { name ->
                var size = 0L
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                bundledSource.open(name).use { input -> size = drain(input, digest) }
                GeoFileInfo(name, size, digest.digest().joinToString("") { "%02x".format(it) })
            }
        } catch (e: IOException) {
            emptyList()
        }
        val id = if (bundled.size == DATABASE_NAMES.size) GeoDataStager.computeDatasetId(bundled) else null
        return GeoDataStatus(
            origin = if (bundled.isEmpty()) GeoDataOrigin.NONE else GeoDataOrigin.BUNDLED,
            datasetId = id,
            files = bundled,
            activatedAtMillis = null,
            activePointerBroken = pointer != null,
            coreDatasetId = coreId,
        )
    }

    private fun drain(input: InputStream, digest: java.security.MessageDigest): Long {
        val buffer = ByteArray(64 * 1024)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) return total
            digest.update(buffer, 0, n)
            total += n
        }
    }

    private fun prepareTemp(dir: File): Boolean {
        if (Files.isSymbolicLink(dir.toPath())) return false
        if (dir.exists()) {
            if (!dir.isDirectory) return false
            val children = dir.listFiles() ?: return false
            if (children.any { Files.isSymbolicLink(it.toPath()) || !it.isFile }) return false
            if (!children.all { it.delete() }) return false
            return true
        }
        return dir.mkdir()
    }

    private fun clearTemp(dir: File) {
        try {
            if (Files.isSymbolicLink(dir.toPath()) || !dir.isDirectory) return
            val children = dir.listFiles() ?: return
            if (children.any { Files.isSymbolicLink(it.toPath()) || !it.isFile }) return
            children.forEach { it.delete() }
            dir.delete()
        } catch (ignored: Exception) {
        }
    }

    companion object {
        const val LOCK_NAME = ".geo-update.lock"
        const val TEMP_NAME = ".geo-download"
        private val DATABASE_NAMES = GeoDataStager.DATABASE_FILES
    }
}
