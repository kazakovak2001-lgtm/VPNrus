package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption

class GeoDataStagerTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val ip = ByteArray(200_000) { (it * 7).toByte() }
    private val site = ByteArray(90_000) { (it * 13 + 1).toByte() }

    /** In-memory bundled assets with failure injection; counts opens so rewrites are observable. */
    private inner class FakeAssets(
        var files: Map<String, ByteArray> = mapOf("geoip.dat" to ip, "geosite.dat" to site),
    ) : GeoAssetSource {
        val missing = mutableSetOf<String>()
        val unreadable = mutableSetOf<String>()
        /** name -> number of bytes after which reading throws (only on the n-th open, 1-based; 0 = every open). */
        val breakAfter = mutableMapOf<String, Int>()
        val breakOnOpen = mutableMapOf<String, Int>()
        /** name -> bytes served from the n-th open onward (a source that changes between hashing and copying). */
        val replaceFromOpen = mutableMapOf<String, Pair<Int, ByteArray>>()
        val opens = mutableMapOf<String, Int>()

        fun totalOpens() = opens.values.sum()

        override fun open(name: String): InputStream {
            val n = (opens[name] ?: 0) + 1
            opens[name] = n
            if (name in missing || name !in files) throw FileNotFoundException("no asset $name")
            if (name in unreadable) throw IOException("asset $name unreadable")
            val replaced = replaceFromOpen[name]
            val data = if (replaced != null && n >= replaced.first) replaced.second else files.getValue(name)
            val after = breakAfter[name]
            val onOpen = breakOnOpen[name] ?: 0
            if (after != null && (onOpen == 0 || onOpen == n)) return BreakingStream(data, after)
            return ByteArrayInputStream(data)
        }
    }

    private class BreakingStream(private val data: ByteArray, private val failAfter: Int) : InputStream() {
        private var pos = 0
        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (pos >= failAfter) throw IOException("boom mid-read")
            val n = minOf(len, failAfter - pos, data.size - pos)
            System.arraycopy(data, pos, b, off, n)
            pos += n
            return n
        }
    }

    private var rootCounter = 0

    /** A fresh, empty `xray-assets` location; every call in a test gets its own parent directory. */
    private fun root(): File = File(tmp.newFolder("nobackup-${rootCounter++}"), "xray-assets")

    private fun stage(root: File, assets: FakeAssets, moveAtomic: ((java.nio.file.Path, java.nio.file.Path) -> Unit)? = null, now: () -> Long = { 1_000L }) =
        if (moveAtomic == null) GeoDataStager(root, assets, nowMillis = now).ensureBundledDataset()
        else GeoDataStager(root, assets, moveAtomic, now).ensureBundledDataset()

    private fun ready(result: GeoDataStagingResult): GeoDataStagingResult.Ready {
        assertTrue("expected Ready but was $result", result is GeoDataStagingResult.Ready)
        return result as GeoDataStagingResult.Ready
    }

    private fun failed(result: GeoDataStagingResult): GeoDataStagingResult.Failed {
        assertTrue("expected Failed but was $result", result is GeoDataStagingResult.Failed)
        return result as GeoDataStagingResult.Failed
    }

    private fun names(dir: File) = dir.list().orEmpty().toSortedSet()

    private fun allFilesBelow(dir: File): List<String> =
        if (!dir.exists()) emptyList() else dir.walkTopDown().filter { it.isFile }.map { it.relativeTo(dir).path.replace('\\', '/') }.sorted().toList()

    // ---- success ----

    @Test
    fun `both bundled assets are staged verified and published as one dataset directory`() {
        val root = root()
        val result = ready(stage(root, FakeAssets()))
        assertEquals(GeoDataOutcome.PUBLISHED, result.outcome)
        assertEquals(root, result.directory.parentFile)
        assertTrue(result.directory.name.startsWith("geo-"))
        assertArrayEquals(ip, File(result.directory, "geoip.dat").readBytes())
        assertArrayEquals(site, File(result.directory, "geosite.dat").readBytes())
        assertEquals(listOf("geoip.dat", "geosite.dat"), result.files.map { it.name })
        assertEquals(listOf(ip.size.toLong(), site.size.toLong()), result.files.map { it.size })
        val marker = JSONObject(File(result.directory, ".geo-dataset.json").readText())
        assertEquals(result.datasetId, marker.getString("datasetId"))
        assertEquals(result.files[0].sha256, marker.getJSONObject("files").getJSONObject("geoip.dat").getString("sha256"))
        assertEquals(setOf(result.directory.name, ".geo-staging.lock"), names(root))
        assertEquals(setOf("geoip.dat", "geosite.dat", ".geo-dataset.json"), names(result.directory))
    }

    @Test
    fun `the dataset id is deterministic and follows the content`() {
        val a = ready(stage(root(), FakeAssets()))
        val b = ready(stage(root(), FakeAssets()))
        assertEquals(a.datasetId, b.datasetId)
        val changed = ready(stage(root(), FakeAssets(mapOf("geoip.dat" to ip, "geosite.dat" to site.copyOf().also { it[0] = (it[0] + 1).toByte() }))))
        assertNotEquals(a.datasetId, changed.datasetId)
    }

    // ---- source failures: nothing is written ----

    @Test
    fun `a missing source asset fails without touching the disk`() {
        val root = root()
        val assets = FakeAssets().apply { missing += "geosite.dat" }
        val f = failed(stage(root, assets))
        assertEquals(GeoDataFailure.SOURCE_MISSING, f.kind)
        assertFalse(root.exists())
    }

    @Test
    fun `an unreadable or empty source asset fails without touching the disk`() {
        val root = root()
        val unreadable = FakeAssets().apply { unreadable += "geoip.dat" }
        assertEquals(GeoDataFailure.SOURCE_UNREADABLE, failed(stage(root, unreadable)).kind)
        val empty = FakeAssets(mapOf("geoip.dat" to ip, "geosite.dat" to ByteArray(0)))
        assertEquals(GeoDataFailure.SOURCE_UNREADABLE, failed(stage(root, empty)).kind)
        val brokenWhileHashing = FakeAssets().apply { breakAfter["geoip.dat"] = 1000 }
        assertEquals(GeoDataFailure.SOURCE_UNREADABLE, failed(stage(root, brokenWhileHashing)).kind)
        assertFalse(root.exists())
    }

    // ---- staging failures: nothing is published ----

    @Test
    fun `an interrupted copy of the first file publishes nothing and leaves no staging data`() {
        val root = root()
        root.mkdirs()
        val unrelated = File(root, "unrelated.bin").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val assets = FakeAssets().apply { breakAfter["geoip.dat"] = 50_000; breakOnOpen["geoip.dat"] = 2 }
        val f = failed(stage(root, assets))
        assertEquals(GeoDataFailure.STAGING_FAILED, f.kind)
        assertTrue(f.detail.contains("boom mid-read"))
        assertFalse(f.detail.contains("\n"))
        assertEquals(setOf("unrelated.bin", ".geo-staging.lock"), names(root))
        assertArrayEquals(byteArrayOf(1, 2, 3), unrelated.readBytes())
        assertTrue(allFilesBelow(root).none { it.contains(".geo-dataset.json") })
    }

    @Test
    fun `a failure while staging the second file publishes no pair and no marker`() {
        val root = root()
        val assets = FakeAssets().apply { breakAfter["geosite.dat"] = 30_000; breakOnOpen["geosite.dat"] = 2 }
        val f = failed(stage(root, assets))
        assertEquals(GeoDataFailure.STAGING_FAILED, f.kind)
        // the first file was fully staged but must not be reachable as a dataset
        assertTrue(root.list().orEmpty().none { it.startsWith("geo-") })
        assertEquals(emptyList<String>(), allFilesBelow(root).filter { it != ".geo-staging.lock" })
    }

    @Test
    fun `a source that changes between hashing and copying is rejected`() {
        val root = root()
        val assets = FakeAssets().apply { replaceFromOpen["geosite.dat"] = 2 to ByteArray(site.size) { 0 } }
        val f = failed(stage(root, assets))
        assertEquals(GeoDataFailure.STAGING_FAILED, f.kind)
        assertTrue(f.detail.contains("changed between hashing and copying"))
        assertTrue(root.list().orEmpty().none { it.startsWith("geo-") })
    }

    @Test
    fun `a failing publish rename leaves no dataset and no marker at the final name`() {
        val root = root()
        val f = failed(
            stage(root, FakeAssets(), moveAtomic = { _, to -> if (to.fileName.toString().startsWith("geo-")) throw IOException("rename refused") }),
        )
        assertEquals(GeoDataFailure.PUBLISH_FAILED, f.kind)
        assertTrue(root.list().orEmpty().none { it.startsWith("geo-") })
        assertEquals(emptyList<String>(), allFilesBelow(root).filter { it != ".geo-staging.lock" })
    }

    @Test
    fun `retry after a failed staging operation succeeds and clears stale staging leftovers`() {
        val root = root()
        val broken = FakeAssets().apply { breakAfter["geosite.dat"] = 30_000; breakOnOpen["geosite.dat"] = 2 }
        failed(stage(root, broken))
        // a crash would leave plain files in the owned staging area
        val staging = File(root, ".geo-staging").apply { mkdirs() }
        File(staging, "geoip.dat.part").writeBytes(byteArrayOf(9, 9))
        val retry = ready(stage(root, FakeAssets()))
        assertEquals(GeoDataOutcome.PUBLISHED, retry.outcome)
        assertArrayEquals(ip, File(retry.directory, "geoip.dat").readBytes())
        assertFalse(File(root, ".geo-staging").exists())
    }

    @Test
    fun `a staging area with unexpected entries is not touched`() {
        val root = root()
        val staging = File(root, ".geo-staging").apply { mkdirs() }
        val nested = File(staging, "nested").apply { mkdirs() }
        val inner = File(nested, "keep.txt").apply { writeText("keep") }
        val f = failed(stage(root, FakeAssets()))
        assertEquals(GeoDataFailure.STAGING_FAILED, f.kind)
        assertTrue(inner.exists())
        assertTrue(root.list().orEmpty().none { it.startsWith("geo-") })
    }

    // ---- existing destination ----

    @Test
    fun `an already verified dataset is left untouched and not rewritten`() {
        val root = root()
        val assets = FakeAssets()
        val first = ready(stage(root, assets))
        val stamps = first.directory.listFiles()!!.associate { it.name to it.lastModified() }
        val opensAfterFirst = assets.totalOpens()
        val second = ready(stage(root, assets))
        assertEquals(GeoDataOutcome.ALREADY_VERIFIED, second.outcome)
        assertEquals(first.directory, second.directory)
        assertEquals(stamps, second.directory.listFiles()!!.associate { it.name to it.lastModified() })
        // only the two hashing reads of the bundled assets; no copy reads
        assertEquals(opensAfterFirst + 2, assets.totalOpens())
    }

    @Test
    fun `repeated initialisation neither corrupts nor rewrites valid data`() {
        val root = root()
        val assets = FakeAssets()
        val first = ready(stage(root, assets))
        val bytes = File(first.directory, "geoip.dat").readBytes()
        repeat(3) {
            val again = ready(stage(root, assets))
            assertEquals(GeoDataOutcome.ALREADY_VERIFIED, again.outcome)
        }
        assertArrayEquals(bytes, File(first.directory, "geoip.dat").readBytes())
        assertEquals(setOf(first.directory.name, ".geo-staging.lock"), names(root))
    }

    @Test
    fun `an own dataset with wrong contents is renamed aside and republished`() {
        for (damage in listOf("flip", "truncate", "missing")) {
            val root = root()
            val first = ready(stage(root, FakeAssets()))
            val target = File(first.directory, "geoip.dat")
            when (damage) {
                "flip" -> target.writeBytes(ip.copyOf().also { it[10] = (it[10] + 1).toByte() })
                "truncate" -> target.writeBytes(ip.copyOf(1000))
                else -> target.delete()
            }
            val damagedBytes = if (target.exists()) target.readBytes() else null
            val second = ready(stage(root, FakeAssets(), now = { 4242L }))
            assertEquals(damage, GeoDataOutcome.REPUBLISHED_AFTER_QUARANTINE, second.outcome)
            assertEquals("${first.directory.name}.quarantine-4242", second.quarantinedAs)
            assertArrayEquals(ip, File(second.directory, "geoip.dat").readBytes())
            val quarantine = File(root, second.quarantinedAs!!)
            assertTrue(quarantine.isDirectory)
            // nothing was deleted: the damaged evidence is preserved
            if (damagedBytes != null) assertArrayEquals(damagedBytes, File(quarantine, "geoip.dat").readBytes())
            assertTrue(File(quarantine, "geosite.dat").exists())
        }
    }

    @Test
    fun `a destination without a valid ownership marker is a conflict and stays untouched`() {
        val root = root()
        val probe = ready(stage(root(), FakeAssets()))
        val foreign = File(root, probe.directory.name).apply { mkdirs() }
        val bytes = byteArrayOf(5, 6, 7)
        File(foreign, "geoip.dat").writeBytes(bytes)
        val noMarker = failed(stage(root, FakeAssets()))
        assertEquals(GeoDataFailure.DESTINATION_CONFLICT, noMarker.kind)
        File(foreign, ".geo-dataset.json").writeText("not json")
        assertEquals(GeoDataFailure.DESTINATION_CONFLICT, failed(stage(root, FakeAssets())).kind)
        File(foreign, ".geo-dataset.json").writeText("""{"schema":1,"datasetId":"other","source":"bundled-apk-assets","files":{}}""")
        assertEquals(GeoDataFailure.DESTINATION_CONFLICT, failed(stage(root, FakeAssets())).kind)
        assertArrayEquals(bytes, File(foreign, "geoip.dat").readBytes())
        assertEquals(setOf(probe.directory.name, ".geo-staging.lock"), names(root))
    }

    @Test
    fun `a symbolic link at the dataset name is never followed or replaced`() {
        val root = root()
        val probe = ready(stage(root(), FakeAssets()))
        root.mkdirs()
        val outside = tmp.newFolder("outside")
        val link = File(root, probe.directory.name)
        val created = try { Files.createSymbolicLink(link.toPath(), outside.toPath()); true } catch (e: Exception) { false }
        assumeTrue("symbolic links are not available here", created)
        val f = failed(stage(root, FakeAssets()))
        assertEquals(GeoDataFailure.DESTINATION_CONFLICT, f.kind)
        assertTrue(outside.list().orEmpty().isEmpty())
    }

    // ---- unrelated data ----

    @Test
    fun `unrelated files and older datasets stay unchanged`() {
        val root = root()
        root.mkdirs()
        val other = File(root, "other").apply { mkdirs() }
        val otherFile = File(other, "keep.bin").apply { writeBytes(byteArrayOf(4, 4)) }
        val loose = File(root, "geoip.dat").apply { writeBytes(byteArrayOf(8)) }
        // an older dataset from a previous bundled version
        val old = ready(stage(root, FakeAssets(mapOf("geoip.dat" to ip.copyOf(5000), "geosite.dat" to site.copyOf(5000)))))
        val oldStamps = old.directory.listFiles()!!.associate { it.name to it.lastModified() }
        val fresh = ready(stage(root, FakeAssets()))
        assertNotEquals(old.directory, fresh.directory)
        assertArrayEquals(byteArrayOf(4, 4), otherFile.readBytes())
        assertArrayEquals(byteArrayOf(8), loose.readBytes())
        assertEquals(oldStamps, old.directory.listFiles()!!.associate { it.name to it.lastModified() })
        assertArrayEquals(ip.copyOf(5000), File(old.directory, "geoip.dat").readBytes())
    }

    // ---- concurrency ----

    @Test
    fun `a concurrent run reports BUSY and changes nothing`() {
        val root = root()
        root.mkdirs()
        FileChannel.open(File(root, ".geo-staging.lock").toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
            val held = channel.tryLock()
            assertTrue(held != null)
            val f = failed(stage(root, FakeAssets()))
            assertEquals(GeoDataFailure.BUSY, f.kind)
            held.release()
        }
        assertEquals(setOf(".geo-staging.lock"), names(root))
        // and once the lock is free the same call works
        ready(stage(root, FakeAssets()))
    }

    // ---- bootstrap ----

    @Test
    fun `bootstrap returns the dataset directory on success and the plain root on every failure`() {
        val root = root()
        val lines = mutableListOf<String>()
        val dir = GeoDataBootstrap.resolveAssetDirectory(root, FakeAssets()) { lines += it }
        assertTrue(dir.name.startsWith("geo-"))
        assertTrue(lines.single().startsWith("geo data: ready"))

        val failLines = mutableListOf<String>()
        val missing = FakeAssets().apply { missing += "geoip.dat" }
        assertEquals(root, GeoDataBootstrap.resolveAssetDirectory(root, missing) { failLines += it })
        assertTrue(failLines.single().contains("SOURCE_MISSING"))

        val throwing = GeoAssetSource { throw IllegalStateException("surprise\nsecond line") }
        val surprise = mutableListOf<String>()
        assertEquals(root, GeoDataBootstrap.resolveAssetDirectory(root, throwing) { surprise += it })
        assertEquals(1, surprise.size)
        assertFalse(surprise.single().contains("\n"))
        assertFalse(surprise.single().contains("\tat "))
    }
}
