package net.pocvpn.client.debug.geoexp

import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

/**
 * M1 debug-only: verified, non-destructive staging of the APK-bundled
 * `geoip.dat` / `geosite.dat` into the `xray-assets` directory for the
 * [Mode.COPIED_ASSETS] mode. Pure `java.io` / `java.nio` (the APK asset
 * source is injected as [OpenSource]), so it is unit-testable on the JVM.
 *
 * Safety rules, all enforced here and none relying on the caller:
 * - NEVER overwrites or deletes anything it does not own. An existing
 *   destination file counts as harness-owned only if a harness marker
 *   ([MARKER_NAME]) in the same directory lists that file with the same
 *   SHA-256 as the APK source AND the file's actual bytes hash to it.
 *   Otherwise (no marker, different hash, symlink, not a regular file,
 *   leftover temp file) the result is a [Plan.conflict]: nothing is written
 *   and the experiment ends as a preparation error.
 * - Every copy is written to a fresh temp file (`<name>.geoexp-tmp`, created
 *   with create-new semantics), flushed to disk, closed, re-read and compared
 *   (size + SHA-256) with the APK source before an atomic rename. A failure
 *   leaves the temp file in place (no cleanup is performed automatically).
 * - The only file ever replaced is the harness's own marker.
 * - Nothing is ever deleted by this object.
 *
 * The remaining race (a foreign writer creating the destination between the
 * ownership check and the rename) cannot occur in a fresh `:xray` process
 * with no VPN active, which the caller guarantees; it is documented here, not
 * eliminated.
 */
internal object GeoAssetStaging {

    const val MARKER_NAME = ".geoexp-owner.json"
    const val TMP_SUFFIX = ".geoexp-tmp"
    private const val BUFFER = 64 * 1024

    /** Opens an APK asset by name (e.g. `context.assets.open(name)`); throws [IOException] if absent. */
    fun interface OpenSource {
        fun open(name: String): InputStream
    }

    data class FileInfo(val name: String, val size: Long, val sha256: String)

    enum class Action { COPY, REUSE_OWNED }

    /** Read-only outcome of the ownership analysis. [conflict] non-null = nothing may be written. */
    data class Plan(val actions: Map<String, Action>, val conflict: String?)

    data class Result(
        val plan: Plan,
        val copied: List<FileInfo>,
        val reused: List<FileInfo>,
        /** Non-null = preparation failed; the core must not be started. Files already moved stay (harness-owned). */
        val error: String?,
    )

    /** Streams [name] from the source once, returning its size and SHA-256. Throws [IOException] if unreadable. */
    fun describe(name: String, source: OpenSource): FileInfo {
        val (size, sha) = source.open(name).use { digest(it) }
        return FileInfo(name, size, sha)
    }

    private fun digest(input: InputStream): Pair<Long, String> {
        val md = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(BUFFER)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
            total += n
        }
        return total to md.digest().joinToString("") { "%02x".format(it) }
    }

    private fun describeFile(file: File): Pair<Long, String> = file.inputStream().use { digest(it) }

    private fun readMarker(dir: File): Map<String, String>? {
        val marker = File(dir, MARKER_NAME)
        if (!marker.exists()) return null
        val files = JSONObject(marker.readText(Charsets.UTF_8)).getJSONObject("files")
        return files.keys().asSequence().associateWith { files.getJSONObject(it).getString("sha256") }
    }

    /** Read-only. Never creates, modifies or deletes anything. */
    fun plan(dir: File, sources: List<FileInfo>): Plan {
        val marker = try { readMarker(dir) } catch (t: Throwable) {
            return Plan(emptyMap(), "ownership marker $MARKER_NAME exists but is unreadable: ${t.javaClass.simpleName}")
        }
        val actions = LinkedHashMap<String, Action>()
        for (src in sources) {
            val dest = File(dir, src.name)
            val tmp = File(dir, src.name + TMP_SUFFIX)
            if (tmp.exists()) return Plan(emptyMap(), "leftover temp file ${tmp.name} exists (manual cleanup required, nothing is deleted automatically)")
            if (!dest.exists() && !Files.isSymbolicLink(dest.toPath())) {
                actions[src.name] = Action.COPY
                continue
            }
            if (Files.isSymbolicLink(dest.toPath())) return Plan(emptyMap(), "${dest.name} is a symbolic link - not touched")
            if (!dest.isFile) return Plan(emptyMap(), "${dest.name} exists and is not a regular file - not touched")
            val markerSha = marker?.get(src.name)
                ?: return Plan(emptyMap(), "${dest.name} already exists and no harness marker claims it - ownership unknown, not touched")
            if (markerSha != src.sha256) return Plan(emptyMap(), "${dest.name} exists but the harness marker records a different SHA-256 than the APK asset - not touched")
            val (_, actualSha) = describeFile(dest)
            if (actualSha != src.sha256) return Plan(emptyMap(), "${dest.name} content no longer matches the harness marker - not touched")
            actions[src.name] = Action.REUSE_OWNED
        }
        return Plan(actions, null)
    }

    /**
     * Stages [sources] into [dir] (which must resolve inside [root]). Writes
     * only after [plan] reports no conflict. Never deletes.
     */
    fun apply(root: File, dir: File, sources: List<FileInfo>, source: OpenSource): Result {
        val dirCanonical = dir.canonicalFile
        if (!dirCanonical.path.startsWith(root.canonicalFile.path + File.separator)) {
            return Result(Plan(emptyMap(), "target directory escapes the app-private root"), emptyList(), emptyList(), "target directory escapes the app-private root")
        }
        val plan = plan(dir, sources)
        if (plan.conflict != null) return Result(plan, emptyList(), emptyList(), plan.conflict)
        val copied = mutableListOf<FileInfo>()
        val reused = mutableListOf<FileInfo>()
        try {
            dir.mkdirs()
            if (plan.actions.values.any { it == Action.COPY }) writeMarker(dir, sources, complete = false)
            for (src in sources) {
                when (plan.actions.getValue(src.name)) {
                    Action.REUSE_OWNED -> reused += src
                    Action.COPY -> {
                        copyVerified(dir, src, source)
                        copied += src
                    }
                }
            }
            if (copied.isNotEmpty()) writeMarker(dir, sources, complete = true)
        } catch (t: Throwable) {
            return Result(plan, copied, reused, "staging failed: ${t.javaClass.simpleName}: ${t.message}")
        }
        return Result(plan, copied, reused, null)
    }

    private fun copyVerified(dir: File, src: FileInfo, source: OpenSource) {
        val tmp = File(dir, src.name + TMP_SUFFIX)
        val dest = File(dir, src.name)
        if (!tmp.createNewFile()) throw IOException("temp file ${tmp.name} already exists")
        val md = MessageDigest.getInstance("SHA-256")
        var written = 0L
        FileOutputStream(tmp).use { out ->
            source.open(src.name).use { input ->
                val buf = ByteArray(BUFFER)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    md.update(buf, 0, n)
                    written += n
                }
            }
            out.flush()
            out.fd.sync()
        }
        val copyPassSha = md.digest().joinToString("") { "%02x".format(it) }
        val (rereadSize, rereadSha) = describeFile(tmp)
        if (written != src.size || rereadSize != src.size) throw IOException("size mismatch for ${src.name}: source=${src.size} written=$written reread=$rereadSize")
        if (copyPassSha != src.sha256 || rereadSha != src.sha256) throw IOException("SHA-256 mismatch for ${src.name}")
        if (dest.exists()) throw IOException("${dest.name} appeared during staging - not overwritten")
        Files.move(tmp.toPath(), dest.toPath(), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun writeMarker(dir: File, sources: List<FileInfo>, complete: Boolean) {
        val files = JSONObject()
        sources.forEach { files.put(it.name, JSONObject().put("size", it.size).put("sha256", it.sha256)) }
        val json = JSONObject().put("schema", 1).put("state", if (complete) "COMPLETE" else "COPYING").put("files", files)
        val tmp = File(dir, MARKER_NAME + TMP_SUFFIX)
        if (!tmp.createNewFile()) throw IOException("marker temp file ${tmp.name} already exists (manual cleanup required)")
        FileOutputStream(tmp).use { out ->
            out.write(json.toString(2).toByteArray(Charsets.UTF_8))
            out.flush()
            out.fd.sync()
        }
        // The marker is the one file this object owns outright and may replace.
        Files.move(tmp.toPath(), File(dir, MARKER_NAME).toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
    }
}
