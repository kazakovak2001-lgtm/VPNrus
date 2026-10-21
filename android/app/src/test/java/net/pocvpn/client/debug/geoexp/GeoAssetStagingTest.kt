package net.pocvpn.client.debug.geoexp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream

class GeoAssetStagingTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val ip = ByteArray(300_000) { (it * 7).toByte() }
    private val site = ByteArray(120_000) { (it * 13 + 1).toByte() }
    private val assets = mapOf("geoip.dat" to ip, "geosite.dat" to site)
    private val source = GeoAssetStaging.OpenSource { name ->
        ByteArrayInputStream(assets[name] ?: throw IOException("no asset $name"))
    }

    private fun sources() = GeoExperimentSpec.DATABASE_FILES.map { GeoAssetStaging.describe(it, source) }

    private fun layout(): Pair<File, File> {
        val root = tmp.newFolder("nobackup")
        return root to File(root, "xray-assets")
    }

    @Test
    fun `describe reports size and sha256`() {
        val info = GeoAssetStaging.describe("geoip.dat", source)
        assertEquals(ip.size.toLong(), info.size)
        assertEquals(64, info.sha256.length)
    }

    @Test
    fun `plan is read only and never creates the directory`() {
        val (_, dir) = layout()
        val plan = GeoAssetStaging.plan(dir, sources())
        assertNull(plan.conflict)
        assertEquals(setOf(GeoAssetStaging.Action.COPY), plan.actions.values.toSet())
        assertFalse(dir.exists())
    }

    @Test
    fun `apply copies both files verified and leaves no temp file`() {
        val (root, dir) = layout()
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNull(result.error)
        assertEquals(2, result.copied.size)
        assertArrayEquals(ip, File(dir, "geoip.dat").readBytes())
        assertArrayEquals(site, File(dir, "geosite.dat").readBytes())
        assertTrue(File(dir, GeoAssetStaging.MARKER_NAME).readText().contains("COMPLETE"))
        assertTrue(dir.list()!!.none { it.endsWith(GeoAssetStaging.TMP_SUFFIX) })
    }

    @Test
    fun `second apply reuses owned files without rewriting them`() {
        val (root, dir) = layout()
        GeoAssetStaging.apply(root, dir, sources(), source)
        val stamp = File(dir, "geoip.dat").lastModified()
        val again = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNull(again.error)
        assertEquals(0, again.copied.size)
        assertEquals(2, again.reused.size)
        assertEquals(stamp, File(dir, "geoip.dat").lastModified())
    }

    @Test
    fun `an existing file without a harness marker is never touched`() {
        val (root, dir) = layout()
        dir.mkdirs()
        val foreign = File(dir, "geoip.dat").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertArrayEquals(byteArrayOf(1, 2, 3), foreign.readBytes())
        assertFalse(File(dir, "geosite.dat").exists())
        assertFalse(File(dir, GeoAssetStaging.MARKER_NAME).exists())
    }

    @Test
    fun `an owned file whose content changed is treated as a conflict and left alone`() {
        val (root, dir) = layout()
        GeoAssetStaging.apply(root, dir, sources(), source)
        File(dir, "geosite.dat").writeBytes(byteArrayOf(9))
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertArrayEquals(byteArrayOf(9), File(dir, "geosite.dat").readBytes())
    }

    @Test
    fun `a leftover temp file blocks staging and is not deleted`() {
        val (root, dir) = layout()
        dir.mkdirs()
        val leftover = File(dir, "geoip.dat" + GeoAssetStaging.TMP_SUFFIX).apply { writeBytes(byteArrayOf(5)) }
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertTrue(leftover.exists())
        assertFalse(File(dir, "geoip.dat").exists())
    }

    @Test
    fun `a source that changes between describe and copy fails without creating the destination`() {
        val (root, dir) = layout()
        val described = sources()
        val flaky = GeoAssetStaging.OpenSource { name ->
            if (name == "geosite.dat") ByteArrayInputStream(ByteArray(site.size) { 0 }) else source.open(name)
        }
        val result = GeoAssetStaging.apply(root, dir, described, flaky)
        assertNotNull(result.error)
        assertTrue(result.error!!.contains("mismatch"))
        assertFalse(File(dir, "geosite.dat").exists())
        // The verified file already moved stays; the failed temp file is kept for inspection.
        assertTrue(File(dir, "geoip.dat").exists())
        assertTrue(File(dir, "geosite.dat" + GeoAssetStaging.TMP_SUFFIX).exists())
    }

    @Test
    fun `a target directory outside the private root is rejected`() {
        val root = tmp.newFolder("root")
        val outside = tmp.newFolder("outside")
        val result = GeoAssetStaging.apply(root, outside, sources(), source)
        assertNotNull(result.error)
        assertTrue(outside.list()!!.isEmpty())
    }

    @Test
    fun `an unreadable marker is a conflict not a crash`() {
        val (root, dir) = layout()
        dir.mkdirs()
        File(dir, GeoAssetStaging.MARKER_NAME).writeText("not json")
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertFalse(File(dir, "geoip.dat").exists())
        assertEquals("not json", File(dir, GeoAssetStaging.MARKER_NAME).readText())
    }

    @Test
    fun `a marker without a files section is a conflict and stays untouched`() {
        val (root, dir) = layout()
        dir.mkdirs()
        val marker = File(dir, GeoAssetStaging.MARKER_NAME).apply { writeText("""{"schema":1}""") }
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertEquals("""{"schema":1}""", marker.readText())
        assertFalse(File(dir, "geoip.dat").exists())
        assertFalse(File(dir, "geosite.dat").exists())
    }

    /** An input stream that delivers [failAfter] bytes and then throws, like a read error halfway through a copy. */
    private class FailingStream(private val data: ByteArray, private val failAfter: Int) : InputStream() {
        private var pos = 0
        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xff
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (pos >= failAfter) throw IOException("boom mid-copy")
            val n = minOf(len, failAfter - pos, data.size - pos)
            System.arraycopy(data, pos, b, off, n)
            pos += n
            return n
        }
    }

    @Test
    fun `a source that throws in the middle of the copy leaves no destination and keeps the partial temp file`() {
        val (root, dir) = layout()
        val described = sources()
        val interrupted = GeoAssetStaging.OpenSource { name ->
            if (name == "geosite.dat") FailingStream(site, 50_000) else source.open(name)
        }
        val result = GeoAssetStaging.apply(root, dir, described, interrupted)
        assertNotNull(result.error)
        assertTrue(result.error!!.contains("boom mid-copy"))
        // the first file was fully verified and moved; the interrupted one never became a destination
        assertArrayEquals(ip, File(dir, "geoip.dat").readBytes())
        assertFalse(File(dir, "geosite.dat").exists())
        val partial = File(dir, "geosite.dat" + GeoAssetStaging.TMP_SUFFIX)
        assertTrue(partial.exists())
        assertEquals(50_000L, partial.length())
        assertTrue(File(dir, GeoAssetStaging.MARKER_NAME).readText().contains("COPYING"))
        // a retry must not guess: the leftover temp file blocks it, and nothing else changes
        val retry = GeoAssetStaging.apply(root, dir, described, source)
        assertNotNull(retry.error)
        assertTrue(partial.exists())
        assertFalse(File(dir, "geosite.dat").exists())
        assertArrayEquals(ip, File(dir, "geoip.dat").readBytes())
    }

    @Test
    fun `a marker whose recorded sha256 differs from the APK asset leaves everything untouched`() {
        val (root, dir) = layout()
        GeoAssetStaging.apply(root, dir, sources(), source)
        val real = sources().associateBy { it.name }
        val tampered = """
            {"schema":1,"state":"COMPLETE","files":{
              "geoip.dat":{"size":${real.getValue("geoip.dat").size},"sha256":"${"0".repeat(64)}"},
              "geosite.dat":{"size":${real.getValue("geosite.dat").size},"sha256":"${real.getValue("geosite.dat").sha256}"}}}
        """.trimIndent()
        val marker = File(dir, GeoAssetStaging.MARKER_NAME).apply { writeText(tampered) }
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertTrue(result.error!!.contains("different SHA-256"))
        assertEquals(tampered, marker.readText())
        assertArrayEquals(ip, File(dir, "geoip.dat").readBytes())
        assertArrayEquals(site, File(dir, "geosite.dat").readBytes())
    }

    @Test
    fun `a destination that is a directory is never touched`() {
        val (root, dir) = layout()
        dir.mkdirs()
        val asDirectory = File(dir, "geoip.dat").apply { mkdir() }
        val result = GeoAssetStaging.apply(root, dir, sources(), source)
        assertNotNull(result.error)
        assertTrue(result.error!!.contains("not a regular file"))
        assertTrue(asDirectory.isDirectory)
        assertFalse(File(dir, "geosite.dat").exists())
        assertFalse(File(dir, GeoAssetStaging.MARKER_NAME).exists())
        assertTrue(dir.list()!!.toSet() == setOf("geoip.dat"))
    }
}
