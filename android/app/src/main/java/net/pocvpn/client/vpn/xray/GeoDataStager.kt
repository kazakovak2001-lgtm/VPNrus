package net.pocvpn.client.vpn.xray

import android.content.res.AssetManager
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest

/** Opens a bundled asset by name. Throws [FileNotFoundException] when the asset does not exist. */
fun interface GeoAssetSource {
    @Throws(IOException::class)
    fun open(name: String): InputStream
}

/** Wraps the APK's [AssetManager] (assets of the AAR are merged into the APK's `assets/`). */
fun AssetManager.asGeoAssetSource(): GeoAssetSource = GeoAssetSource { name -> open(name) }

data class GeoFileInfo(val name: String, val size: Long, val sha256: String)

enum class GeoDataOutcome {
    /** The dataset directory already existed and every file re-verified; nothing was written. */
    ALREADY_VERIFIED,

    /** A new dataset directory was staged, verified and published. */
    PUBLISHED,

    /** The existing (own, damaged) dataset directory was renamed aside, then a fresh one was published. */
    REPUBLISHED_AFTER_QUARANTINE,
}

enum class GeoDataFailure {
    /** A bundled asset does not exist. */
    SOURCE_MISSING,

    /** A bundled asset could not be read, or is empty. */
    SOURCE_UNREADABLE,

    /** Writing or verifying the staged files failed (incl. a source that changed between hashing and copying). */
    STAGING_FAILED,

    /** The fully staged dataset did not verify. */
    VERIFICATION_FAILED,

    /** The final rename (or the quarantine rename) failed. */
    PUBLISH_FAILED,

    /** The target name exists but is not a dataset directory this code owns - left untouched. */
    DESTINATION_CONFLICT,

    /** Another staging run holds the lock - nothing was changed. */
    BUSY,
}

sealed class GeoDataStagingResult {
    /** The pair is complete and verified in [directory]; [files] are the verified sizes and SHA-256 values. */
    data class Ready(
        val directory: File,
        val datasetId: String,
        val files: List<GeoFileInfo>,
        val outcome: GeoDataOutcome,
        val quarantinedAs: String? = null,
    ) : GeoDataStagingResult()

    /** Never success. [detail] is one short line (exception class and trimmed message), never a stack trace. */
    data class Failed(val kind: GeoDataFailure, val detail: String) : GeoDataStagingResult()
}

/**
 * Phase A - makes the BUNDLED `geoip.dat` / `geosite.dat` available to the Xray core as one verified
 * dataset, deterministically and without any network access.
 *
 * Why an explicit copy is needed: the pinned Xray-core resolves a database through
 * `getAssetFileLocation`, which returns the `os.Stat` error for a file missing from the asset
 * directory BEFORE the wrapper's `mobasset` fallback reader would run (static analysis of the pinned
 * sources; not verified at runtime on a device). The APK assets therefore have to exist as real files.
 *
 * Layout under [root] (`noBackupFilesDir/xray-assets`):
 * - `geo-<id>/` - one published dataset: `geoip.dat`, `geosite.dat` and an ownership/integrity marker
 *   `.geo-dataset.json`. `<id>` is derived from the SHA-256 of both files, so a dataset is
 *   content-addressed and an existing directory is never rewritten in place.
 * - `.geo-staging/` - the only place files are written, deleted or replaced. Created fresh per attempt.
 * - `.geo-staging.lock` - a lock file serialising concurrent attempts.
 * Everything else under [root] is never read, modified or deleted.
 *
 * Guarantees actually provided:
 * - The pair is published by ONE directory rename (atomic on the same filesystem), so a half-copied
 *   pair is never visible under the final `geo-<id>` name; the marker lives inside that directory, so
 *   no marker or pointer exists for an incomplete pair.
 * - Each file is staged to a `.part` file, fsynced, re-read and compared (size and SHA-256) with the
 *   hash of the bundled asset, and only then renamed inside the staging area. The whole staged
 *   directory is verified again before the publish rename.
 * - A correct existing dataset is re-verified (size and SHA-256) and left untouched.
 * - Nothing is ever deleted outside the staging area. A damaged dataset directory that carries this
 *   code's ownership marker is renamed aside (`.quarantine-<ms>`), not removed; a directory without a
 *   valid marker is reported as a conflict and never touched. Older datasets are left in place.
 *
 * Not guaranteed / not claimed: durability of the rename itself (no directory fsync from Java; if
 * power is lost right after the rename the next call simply re-verifies and, if needed, republishes);
 * two renames elsewhere (e.g. flat `xray-assets/geoip.dat` plus `geosite.dat`) would NOT be pairwise
 * atomic, which is why the directory layout is used.
 *
 * Runtime safety: callers must use it before the first core start of a process (see
 * [GeoDataBootstrap]); this class itself never touches an existing, valid dataset, so a core that is
 * reading one is unaffected. The files are expected to be read when the core is built; that they are
 * not read lazily later is a static conclusion that is not verified at runtime.
 */
class GeoDataStager(
    private val root: File,
    private val source: GeoAssetSource,
    /** Atomic rename; injectable so tests can make a publish fail. Must not replace an existing target. */
    private val moveAtomic: (Path, Path) -> Unit = { from, to -> Files.move(from, to, StandardCopyOption.ATOMIC_MOVE) },
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {

    fun ensureBundledDataset(): GeoDataStagingResult {
        val sources = try {
            describeSources()
        } catch (e: FileNotFoundException) {
            return GeoDataStagingResult.Failed(GeoDataFailure.SOURCE_MISSING, brief(e))
        } catch (e: IOException) {
            return GeoDataStagingResult.Failed(GeoDataFailure.SOURCE_UNREADABLE, brief(e))
        }

        if (!root.isDirectory && !root.mkdirs()) {
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "cannot create ${root.name}")
        }
        val channel = try {
            FileChannel.open(File(root, LOCK_NAME).toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (e: IOException) {
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "lock file: ${brief(e)}")
        }
        val lock = try {
            channel.tryLock()
        } catch (e: OverlappingFileLockException) {
            null
        } catch (e: IOException) {
            channel.close()
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "lock: ${brief(e)}")
        }
        if (lock == null) {
            channel.close()
            return GeoDataStagingResult.Failed(GeoDataFailure.BUSY, "another staging run holds the lock")
        }
        try {
            return publishLocked(sources)
        } finally {
            try { lock.release() } catch (ignored: IOException) { }
            try { channel.close() } catch (ignored: IOException) { }
        }
    }

    private fun publishLocked(sources: List<GeoFileInfo>): GeoDataStagingResult {
        val id = datasetId(sources)
        val finalDir = File(root, DATASET_PREFIX + id)
        var quarantinedAs: String? = null

        if (finalDir.exists() || Files.isSymbolicLink(finalDir.toPath())) {
            when (val state = verifyDataset(finalDir, id, sources)) {
                is DatasetState.Verified ->
                    return GeoDataStagingResult.Ready(finalDir, id, sources, GeoDataOutcome.ALREADY_VERIFIED)
                is DatasetState.Foreign ->
                    return GeoDataStagingResult.Failed(GeoDataFailure.DESTINATION_CONFLICT, "${finalDir.name}: ${state.reason}")
                is DatasetState.Damaged -> {
                    // Own directory (valid marker) with wrong content: rename aside, never delete.
                    val quarantine = uniqueQuarantineName(finalDir)
                    try {
                        moveAtomic(finalDir.toPath(), quarantine.toPath())
                    } catch (e: Exception) {
                        return GeoDataStagingResult.Failed(GeoDataFailure.PUBLISH_FAILED, "quarantine rename: ${brief(e)}")
                    }
                    quarantinedAs = quarantine.name
                }
            }
        }

        val staging = File(root, STAGING_NAME)
        try {
            prepareStaging(staging)?.let { return it }
            for (info in sources) copyVerified(staging, info)
            writeMarker(staging, id, sources)
            when (val state = verifyDataset(staging, id, sources)) {
                is DatasetState.Verified -> Unit
                is DatasetState.Foreign -> return GeoDataStagingResult.Failed(GeoDataFailure.VERIFICATION_FAILED, state.reason)
                is DatasetState.Damaged -> return GeoDataStagingResult.Failed(GeoDataFailure.VERIFICATION_FAILED, state.reason)
            }
            try {
                moveAtomic(staging.toPath(), finalDir.toPath())
            } catch (e: Exception) {
                return GeoDataStagingResult.Failed(GeoDataFailure.PUBLISH_FAILED, "publish rename: ${brief(e)}")
            }
            return GeoDataStagingResult.Ready(
                finalDir,
                id,
                sources,
                if (quarantinedAs != null) GeoDataOutcome.REPUBLISHED_AFTER_QUARANTINE else GeoDataOutcome.PUBLISHED,
                quarantinedAs,
            )
        } catch (e: StagingException) {
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, e.message ?: "staging failed")
        } catch (e: IOException) {
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, brief(e))
        } finally {
            // Best effort, inside the owned staging area only. After a successful publish it no longer exists.
            clearStagingBestEffort(staging)
        }
    }

    // ---- sources -------------------------------------------------------------------------------

    private fun describeSources(): List<GeoFileInfo> = DATABASE_FILES.map { name ->
        val (size, sha) = source.open(name).use { hash(it) }
        if (size <= 0L) throw IOException("bundled asset $name is empty")
        GeoFileInfo(name, size, sha)
    }

    private fun datasetId(sources: List<GeoFileInfo>): String {
        val text = sources.joinToString("") { "${it.name}:${it.sha256}\n" }
        return sha256Hex(text.toByteArray(Charsets.UTF_8)).take(ID_LENGTH)
    }

    // ---- staging -------------------------------------------------------------------------------

    private class StagingException(message: String) : IOException(message)

    /** Returns a failure result, or null when [staging] is an empty directory ready for use. */
    private fun prepareStaging(staging: File): GeoDataStagingResult.Failed? {
        val path = staging.toPath()
        if (Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            if (Files.isSymbolicLink(path) || !staging.isDirectory) {
                return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "${staging.name} is not a plain directory - not touched")
            }
            val children = staging.listFiles() ?: return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "cannot list ${staging.name}")
            if (children.any { Files.isSymbolicLink(it.toPath()) || !it.isFile }) {
                return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "${staging.name} contains unexpected entries - not touched")
            }
            // Leftovers of an interrupted attempt: plain files inside the owned staging area.
            for (child in children) {
                if (!child.delete()) return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "cannot clear ${staging.name}/${child.name}")
            }
        } else if (!staging.mkdir()) {
            return GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "cannot create ${staging.name}")
        }
        return null
    }

    private fun copyVerified(staging: File, info: GeoFileInfo) {
        val part = File(staging, info.name + PART_SUFFIX)
        val dest = File(staging, info.name)
        if (!part.createNewFile()) throw StagingException("${part.name} already exists")
        val md = MessageDigest.getInstance("SHA-256")
        var written = 0L
        FileOutputStream(part).use { out ->
            source.open(info.name).use { input ->
                val buffer = ByteArray(BUFFER)
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    out.write(buffer, 0, n)
                    md.update(buffer, 0, n)
                    written += n
                }
            }
            out.flush()
            out.fd.sync()
        }
        val copiedSha = md.digest().toHex()
        if (written != info.size || copiedSha != info.sha256) {
            throw StagingException("${info.name} changed between hashing and copying (size $written vs ${info.size})")
        }
        val (rereadSize, rereadSha) = part.inputStream().use { hash(it) }
        if (rereadSize != info.size || rereadSha != info.sha256) {
            throw StagingException("${info.name} did not read back identically from staging")
        }
        Files.move(part.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun writeMarker(dir: File, id: String, sources: List<GeoFileInfo>) {
        val files = JSONObject()
        sources.forEach { files.put(it.name, JSONObject().put("size", it.size).put("sha256", it.sha256)) }
        val json = JSONObject()
            .put("schema", MARKER_SCHEMA)
            .put("datasetId", id)
            .put("source", MARKER_SOURCE)
            .put("files", files)
        val part = File(dir, MARKER_NAME + PART_SUFFIX)
        if (!part.createNewFile()) throw StagingException("${part.name} already exists")
        FileOutputStream(part).use { out ->
            out.write(json.toString(2).toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync()
        }
        Files.move(part.toPath(), File(dir, MARKER_NAME).toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun clearStagingBestEffort(staging: File) {
        try {
            val path = staging.toPath()
            if (!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path) || !staging.isDirectory) return
            val children = staging.listFiles() ?: return
            // Only plain files are removed; anything else means this is not our area any more - leave it.
            if (children.any { Files.isSymbolicLink(it.toPath()) || !it.isFile }) return
            children.forEach { it.delete() }
            staging.delete()
        } catch (ignored: Exception) {
            // Best effort only: a leftover is cleared by the next attempt's prepareStaging().
        }
    }

    // ---- verification --------------------------------------------------------------------------

    private sealed class DatasetState {
        object Verified : DatasetState()
        /** Not a dataset directory this code owns (or unreadable marker) - must not be touched. */
        data class Foreign(val reason: String) : DatasetState()
        /** Carries this code's valid marker for this dataset id, but a file is missing or wrong. */
        data class Damaged(val reason: String) : DatasetState()
    }

    private fun verifyDataset(dir: File, id: String, sources: List<GeoFileInfo>): DatasetState {
        val dirPath = dir.toPath()
        if (Files.isSymbolicLink(dirPath) || !dir.isDirectory) return DatasetState.Foreign("not a plain directory")
        val markerFile = File(dir, MARKER_NAME)
        if (Files.isSymbolicLink(markerFile.toPath()) || !markerFile.isFile) return DatasetState.Foreign("no ownership marker")
        val marker = try {
            JSONObject(markerFile.readText(Charsets.UTF_8))
        } catch (e: Exception) {
            return DatasetState.Foreign("unreadable ownership marker")
        }
        if (marker.optInt("schema", -1) != MARKER_SCHEMA || marker.optString("datasetId") != id || marker.optString("source") != MARKER_SOURCE) {
            return DatasetState.Foreign("ownership marker belongs to a different dataset")
        }
        val recorded = marker.optJSONObject("files") ?: return DatasetState.Damaged("marker has no file list")
        for (info in sources) {
            val entry = recorded.optJSONObject(info.name)
            if (entry == null || entry.optLong("size", -1L) != info.size || entry.optString("sha256") != info.sha256) {
                return DatasetState.Damaged("marker does not describe ${info.name} as bundled")
            }
            val file = File(dir, info.name)
            if (Files.isSymbolicLink(file.toPath()) || !file.isFile) return DatasetState.Damaged("${info.name} missing or not a regular file")
            if (file.length() != info.size) return DatasetState.Damaged("${info.name} has the wrong length")
            val (_, sha) = try {
                file.inputStream().use { hash(it) }
            } catch (e: IOException) {
                return DatasetState.Damaged("${info.name} unreadable")
            }
            if (sha != info.sha256) return DatasetState.Damaged("${info.name} has the wrong SHA-256")
        }
        return DatasetState.Verified
    }

    private fun uniqueQuarantineName(finalDir: File): File {
        val base = "${finalDir.name}$QUARANTINE_INFIX${nowMillis()}"
        var candidate = File(root, base)
        var n = 1
        while (candidate.exists() || Files.isSymbolicLink(candidate.toPath())) {
            candidate = File(root, "$base-$n")
            n++
        }
        return candidate
    }

    // ---- helpers -------------------------------------------------------------------------------

    private fun hash(input: InputStream): Pair<Long, String> {
        val md = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(BUFFER)
        var total = 0L
        while (true) {
            val n = input.read(buffer)
            if (n < 0) break
            md.update(buffer, 0, n)
            total += n
        }
        return total to md.digest().toHex()
    }

    private fun sha256Hex(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun brief(t: Throwable): String = "${t.javaClass.simpleName}: ${t.message.orEmpty().replace('\n', ' ').take(160)}"

    companion object {
        const val GEOIP_FILE = "geoip.dat"
        const val GEOSITE_FILE = "geosite.dat"
        val DATABASE_FILES: List<String> = listOf(GEOIP_FILE, GEOSITE_FILE)

        const val DATASET_PREFIX = "geo-"
        const val STAGING_NAME = ".geo-staging"
        const val LOCK_NAME = ".geo-staging.lock"
        const val MARKER_NAME = ".geo-dataset.json"
        const val PART_SUFFIX = ".part"
        const val QUARANTINE_INFIX = ".quarantine-"
        const val MARKER_SCHEMA = 1
        const val MARKER_SOURCE = "bundled-apk-assets"
        private const val ID_LENGTH = 16
        private const val BUFFER = 64 * 1024
    }
}

/**
 * Chooses the directory handed to `Libv2ray.initCoreEnv` (as `xray.location.asset`). It never throws
 * and never makes VPN startup depend on the geo data: whatever happens, the caller gets a usable
 * directory, falling back to [root] - exactly what the code used before this phase.
 */
object GeoDataBootstrap {

    fun resolveAssetDirectory(root: File, source: GeoAssetSource, log: (String) -> Unit = {}): File {
        val result = try {
            GeoDataStager(root, source).ensureBundledDataset()
        } catch (t: Throwable) {
            GeoDataStagingResult.Failed(GeoDataFailure.STAGING_FAILED, "${t.javaClass.simpleName}: ${t.message.orEmpty().replace('\n', ' ').take(160)}")
        }
        return when (result) {
            is GeoDataStagingResult.Ready -> {
                log("geo data: ready outcome=${result.outcome} id=${result.datasetId} dir=${result.directory.name}")
                result.directory
            }
            is GeoDataStagingResult.Failed -> {
                log("geo data: NOT available (${result.kind}): ${result.detail}")
                root
            }
        }
    }
}
