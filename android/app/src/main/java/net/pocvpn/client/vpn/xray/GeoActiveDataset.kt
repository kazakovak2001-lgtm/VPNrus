package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/** A dataset directory whose marker and every file were re-verified (size and SHA-256). */
data class GeoDatasetInfo(
    val directory: File,
    val datasetId: String,
    /** The marker's `source`: [GeoDataStager.MARKER_SOURCE] or [GeoDataStager.SOURCE_DOWNLOADED]. */
    val source: String,
    val files: List<GeoFileInfo>,
)

/** `previous` is the dataset that was active before `active`; it is kept on disk so the last working pair can be restored. */
data class GeoActivePointer(val active: String, val previous: String?, val activatedAtMillis: Long)

/**
 * The user-activated geo dataset (Settings -> GeoData): a tiny pointer file `.geo-active.json` in the
 * `xray-assets` root naming one `geo-<id>` directory published by [GeoDataStager].
 *
 * Why a pointer and not "newest directory wins": activation must be one atomic step that happens only after
 * a new pair is fully downloaded, validated and published. The pointer is written to a temp file and moved
 * into place (atomic replace), so a reader sees either the old or the new dataset, never a half state, and
 * a failed update leaves the old pointer - and therefore the old working databases - untouched.
 *
 * The pointer is only trusted after [inspect] re-verified the dataset it names. A missing, corrupt or
 * damaged pointer/dataset resolves to `null`, and [GeoDataBootstrap] then falls back to the bundled
 * databases. Nothing in this object ever modifies an existing dataset directory.
 */
object GeoActiveDataset {

    const val POINTER_NAME = ".geo-active.json"
    private const val POINTER_SCHEMA = 1

    fun readPointer(root: File): GeoActivePointer? {
        val file = File(root, POINTER_NAME)
        if (Files.isSymbolicLink(file.toPath()) || !file.isFile) return null
        return try {
            val json = JSONObject(file.readText(Charsets.UTF_8))
            if (json.optInt("schema", -1) != POINTER_SCHEMA) return null
            val active = json.optString("active")
            if (!isDatasetId(active)) return null
            val previous = json.optString("previous").takeIf { it.isNotEmpty() && isDatasetId(it) }
            GeoActivePointer(active, previous, json.optLong("activatedAtMillis", 0L))
        } catch (e: Exception) {
            null
        }
    }

    /** Atomically replaces the pointer. Throws [IOException] when it cannot; the old pointer is then unchanged. */
    @Throws(IOException::class)
    fun writePointer(root: File, pointer: GeoActivePointer) {
        if (!isDatasetId(pointer.active)) throw IOException("invalid dataset id")
        root.mkdirs()
        val json = JSONObject()
            .put("schema", POINTER_SCHEMA)
            .put("active", pointer.active)
            .put("previous", pointer.previous ?: "")
            .put("activatedAtMillis", pointer.activatedAtMillis)
        val tmp = File(root, "$POINTER_NAME.tmp")
        java.io.FileOutputStream(tmp).use { out ->
            out.write(json.toString(2).toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync()
        }
        try {
            Files.move(tmp.toPath(), File(root, POINTER_NAME).toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (e: IOException) {
            tmp.delete()
            throw IOException("could not activate dataset: ${e.javaClass.simpleName}", e)
        }
    }

    /** Removes only the pointer file; datasets stay on disk. Returns false when the pointer exists but cannot be removed. */
    fun clearPointer(root: File): Boolean {
        val file = File(root, POINTER_NAME)
        return !file.exists() || file.delete()
    }

    /** Changes whenever the pointer file is replaced; cheap enough to compare on every connect. */
    fun pointerSignature(root: File): String {
        val file = File(root, POINTER_NAME)
        return if (file.isFile) "${file.lastModified()}:${file.length()}" else "none"
    }

    /** The active dataset, re-verified, or null when there is no pointer or the pointed-to dataset is not intact. */
    fun resolveVerified(root: File): GeoDatasetInfo? {
        val pointer = readPointer(root) ?: return null
        val info = inspect(File(root, GeoDataStager.DATASET_PREFIX + pointer.active)) ?: return null
        return if (info.datasetId == pointer.active) info else null
    }

    /**
     * Verifies a dataset directory on its own evidence: the marker must be ours (schema, known source), name
     * both database files with size and SHA-256, its dataset id must equal the id derived from those hashes
     * and the directory name, and the files on disk must match the marker byte for byte (size and SHA-256).
     */
    fun inspect(dir: File): GeoDatasetInfo? {
        return try {
            val dirPath = dir.toPath()
            if (Files.isSymbolicLink(dirPath) || !dir.isDirectory) return null
            val markerFile = File(dir, GeoDataStager.MARKER_NAME)
            if (Files.isSymbolicLink(markerFile.toPath()) || !markerFile.isFile) return null
            val marker = JSONObject(markerFile.readText(Charsets.UTF_8))
            if (marker.optInt("schema", -1) != GeoDataStager.MARKER_SCHEMA) return null
            val source = marker.optString("source")
            if (source !in GeoDataStager.KNOWN_SOURCES) return null
            val recorded = marker.optJSONObject("files") ?: return null
            val files = GeoDataStager.DATABASE_FILES.map { name ->
                val entry = recorded.optJSONObject(name) ?: return null
                GeoFileInfo(name, entry.optLong("size", -1L), entry.optString("sha256"))
            }
            if (files.any { it.size <= 0L || it.sha256.length != 64 }) return null
            val id = GeoDataStager.computeDatasetId(files)
            if (marker.optString("datasetId") != id || dir.name != GeoDataStager.DATASET_PREFIX + id) return null
            for (info in files) {
                val file = File(dir, info.name)
                if (Files.isSymbolicLink(file.toPath()) || !file.isFile || file.length() != info.size) return null
                if (sha256(file) != info.sha256) return null
            }
            GeoDatasetInfo(dir, id, source, files)
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Deletes downloaded datasets (marker source [GeoDataStager.SOURCE_DOWNLOADED]) whose id is not in [keepIds].
     * It never touches the bundled dataset, quarantined directories, directories without our marker, symlinks or
     * anything that is not a plain directory of plain files. Returns the ids that were removed.
     */
    fun prune(root: File, keepIds: Set<String>): List<String> {
        val removed = mutableListOf<String>()
        val dirs = root.listFiles() ?: return removed
        for (dir in dirs) {
            val name = dir.name
            if (!name.startsWith(GeoDataStager.DATASET_PREFIX) || name.contains(GeoDataStager.QUARANTINE_INFIX)) continue
            if (Files.isSymbolicLink(dir.toPath()) || !dir.isDirectory) continue
            val id = name.removePrefix(GeoDataStager.DATASET_PREFIX)
            if (id in keepIds) continue
            val source = try {
                JSONObject(File(dir, GeoDataStager.MARKER_NAME).readText(Charsets.UTF_8)).optString("source")
            } catch (e: Exception) {
                continue
            }
            if (source != GeoDataStager.SOURCE_DOWNLOADED) continue
            val children = dir.listFiles() ?: continue
            if (children.any { Files.isSymbolicLink(it.toPath()) || !it.isFile }) continue
            if (children.all { it.delete() } && dir.delete()) removed += id
        }
        return removed
    }

    private fun isDatasetId(value: String): Boolean = value.length == 16 && value.all { it in '0'..'9' || it in 'a'..'f' }

    internal fun sha256(file: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buffer)
                if (n < 0) break
                md.update(buffer, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
}
