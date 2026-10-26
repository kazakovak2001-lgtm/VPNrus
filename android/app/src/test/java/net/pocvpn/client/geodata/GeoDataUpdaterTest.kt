package net.pocvpn.client.geodata

import net.pocvpn.client.vpn.xray.GeoActiveDataset
import net.pocvpn.client.vpn.xray.GeoAssetDirProvider
import net.pocvpn.client.vpn.xray.GeoDataBootstrap
import net.pocvpn.client.vpn.xray.GeoDataOrigin
import net.pocvpn.client.vpn.xray.GeoDataStager
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption

class GeoDataUpdaterTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val ipUrl = "https://one.example.org/geoip.dat"
    private val siteUrl = "https://two.other.example.net/lists/geosite.dat"
    private val settings = GeoDataSettings(ipUrl, siteUrl)

    private lateinit var root: File
    private val bundled = FakeBundled()
    private val http = FakeHttp()
    private var clock = 1_000L

    private fun newRoot(): File = File(tmp.newFolder("nobackup${System.nanoTime()}"), "xray-assets").also { root = it }

    private fun updater(r: File = root, h: FakeHttp = http, bundledSource: FakeBundled = bundled) =
        GeoDataUpdater(r, bundledSource, GeoDatabaseDownloader(h), nowMillis = { clock++ })

    private fun resolve() = GeoDataBootstrap.resolve(root, bundled)

    private fun geoDirs() = root.listFiles()!!.filter { it.isDirectory && it.name.startsWith("geo-") && !it.name.contains(".quarantine-") }.map { it.name }.toSet()

    private fun serveV2() {
        http.serve(ipUrl, GeoTestData.geoipV2)
        http.serve(siteUrl, GeoTestData.geositeV2)
    }

    // ---- success and activation ----

    @Test
    fun `before any update the bundled databases are what the core gets`() {
        newRoot()
        val r = resolve()
        assertEquals(GeoDataOrigin.BUNDLED, r.origin)
        assertArrayEquals(GeoTestData.geoipV1, File(r.directory, "geoip.dat").readBytes())
        assertArrayEquals(GeoTestData.geositeV1, File(r.directory, "geosite.dat").readBytes())
    }

    @Test
    fun `a successful update activates the new pair and the core path now contains it`() {
        newRoot()
        serveV2()
        val result = updater().update(settings)
        val updated = result as GeoUpdateResult.Updated
        assertEquals(listOf(GeoDatabaseKind.GEOIP, GeoDatabaseKind.GEOSITE), updated.changed)

        val r = resolve()
        assertEquals(GeoDataOrigin.DOWNLOADED, r.origin)
        assertEquals(updated.datasetId, r.datasetId)
        // The directory the core is pointed at (xray.location.asset) holds both files at its top level.
        assertEquals(setOf("geoip.dat", "geosite.dat", ".geo-dataset.json"), r.directory.list()!!.toSet())
        assertArrayEquals(GeoTestData.geoipV2, File(r.directory, "geoip.dat").readBytes())
        assertArrayEquals(GeoTestData.geositeV2, File(r.directory, "geosite.dat").readBytes())
    }

    @Test
    fun `the status reports the downloaded pair`() {
        newRoot()
        serveV2()
        val before = updater().status()
        assertEquals(GeoDataOrigin.BUNDLED, before.origin)
        assertEquals(2, before.files.size)
        updater().update(settings)
        val after = updater().status()
        assertEquals(GeoDataOrigin.DOWNLOADED, after.origin)
        assertTrue(after.activatedAtMillis!! > 0)
        assertFalse(after.activePointerBroken)
    }

    @Test
    fun `with one url only that file changes and the other is carried over`() {
        newRoot()
        http.serve(ipUrl, GeoTestData.geoipV2)
        val result = updater().update(GeoDataSettings(geoipUrl = ipUrl))
        assertEquals(listOf(GeoDatabaseKind.GEOIP), (result as GeoUpdateResult.Updated).changed)
        val r = resolve()
        assertArrayEquals(GeoTestData.geoipV2, File(r.directory, "geoip.dat").readBytes())
        assertArrayEquals("the untouched file comes from the previous databases", GeoTestData.geositeV1, File(r.directory, "geosite.dat").readBytes())
        assertEquals(listOf(ipUrl), http.requested)
    }

    @Test
    fun `a second update carries the previous download over for the file without a url`() {
        newRoot()
        serveV2()
        updater().update(settings)
        val v3site = GeoTestData.geosite("GOOGLE", "YANDEX", "CN", "RU")
        http.serve(siteUrl, v3site)
        val result = updater().update(GeoDataSettings(geositeUrl = siteUrl))
        assertTrue(result is GeoUpdateResult.Updated)
        val r = resolve()
        assertArrayEquals(GeoTestData.geoipV2, File(r.directory, "geoip.dat").readBytes())
        assertArrayEquals(v3site, File(r.directory, "geosite.dat").readBytes())
    }

    @Test
    fun `identical files are reported as already current and change nothing`() {
        newRoot()
        serveV2()
        val first = updater().update(settings) as GeoUpdateResult.Updated
        val pointerBefore = File(root, GeoActiveDataset.POINTER_NAME).readText()
        val second = updater().update(settings)
        assertEquals(GeoUpdateResult.AlreadyCurrent(first.datasetId), second)
        assertEquals(pointerBefore, File(root, GeoActiveDataset.POINTER_NAME).readText())
    }

    @Test
    fun `downloading the same bytes as the bundled databases does not conflict with the bundled dataset`() {
        newRoot()
        // stage the bundled dataset first (what the core does at its first start)
        val staged = resolve()
        http.serve(ipUrl, GeoTestData.geoipV1)
        http.serve(siteUrl, GeoTestData.geositeV1)
        val result = updater().update(settings)
        assertTrue("expected success, was $result", result is GeoUpdateResult.Updated)
        assertEquals(staged.datasetId, (result as GeoUpdateResult.Updated).datasetId)
        assertEquals(GeoDataOrigin.DOWNLOADED, resolve().origin)
    }

    // ---- failure keeps the previous databases ----

    private fun assertStillOnBundled() {
        val r = resolve()
        assertEquals(GeoDataOrigin.BUNDLED, r.origin)
        assertArrayEquals(GeoTestData.geoipV1, File(r.directory, "geoip.dat").readBytes())
        assertNull(GeoActiveDataset.readPointer(root))
    }

    @Test
    fun `http errors keep the previous databases`() {
        newRoot()
        resolve()
        http.status(ipUrl, 404)
        http.serve(siteUrl, GeoTestData.geositeV2)
        val failed = updater().update(settings) as GeoUpdateResult.Failed
        assertEquals(GeoUpdateFailureKind.DOWNLOAD_FAILED, failed.kind)
        assertEquals(GeoDatabaseKind.GEOIP, failed.file)
        assertEquals(404, failed.httpStatus)
        assertStillOnBundled()
    }

    @Test
    fun `a valid first file is not activated when the second file is invalid`() {
        newRoot()
        resolve()
        http.serve(ipUrl, GeoTestData.geoipV2)
        http.serve(siteUrl, "<html>maintenance</html>".toByteArray(), contentType = "text/html")
        val failed = updater().update(settings) as GeoUpdateResult.Failed
        assertEquals(GeoDatabaseKind.GEOSITE, failed.file)
        assertEquals(GeoInvalidReason.LOOKS_LIKE_HTML, failed.invalidReason)
        assertStillOnBundled()
        assertEquals("no new dataset directory was published", 1, geoDirs().size)
    }

    @Test
    fun `an interrupted download keeps the previous databases and leaves no temp data`() {
        newRoot()
        resolve()
        http.serve(ipUrl, GeoTestData.geoipV2)
        http.breakMidway(siteUrl, GeoTestData.geositeV2, afterBytes = 30)
        val failed = updater().update(settings) as GeoUpdateResult.Failed
        assertEquals(GeoDownloadFailure.INTERRUPTED, failed.download)
        assertStillOnBundled()
        assertFalse(File(root, GeoDataUpdater.TEMP_NAME).exists())
    }

    @Test
    fun `a failed update after a good one keeps the good one`() {
        newRoot()
        serveV2()
        val good = updater().update(settings) as GeoUpdateResult.Updated
        http.status(ipUrl, 500)
        val failed = updater().update(settings)
        assertTrue(failed is GeoUpdateResult.Failed)
        val r = resolve()
        assertEquals(GeoDataOrigin.DOWNLOADED, r.origin)
        assertEquals(good.datasetId, r.datasetId)
    }

    @Test
    fun `no configured url and invalid urls fail before any network access`() {
        newRoot()
        assertEquals(GeoUpdateFailureKind.NOT_CONFIGURED, (updater().update(GeoDataSettings()) as GeoUpdateResult.Failed).kind)
        val bad = updater().update(GeoDataSettings(geoipUrl = "http://example.org/geoip.dat")) as GeoUpdateResult.Failed
        assertEquals(GeoUpdateFailureKind.INVALID_URL, bad.kind)
        assertEquals(GeoDatabaseKind.GEOIP, bad.file)
        assertTrue(http.requested.isEmpty())
    }

    @Test
    fun `a failing pointer write leaves the previous activation in place`() {
        newRoot()
        serveV2()
        val good = updater().update(settings) as GeoUpdateResult.Updated
        // make the pointer unreplaceable: a directory at the temp name makes writePointer fail
        File(root, GeoActiveDataset.POINTER_NAME + ".tmp").mkdirs()
        http.serve(ipUrl, GeoTestData.geoip("CN", "RU", "US", "DE", "FR"))
        val failed = updater().update(settings) as GeoUpdateResult.Failed
        assertEquals(GeoUpdateFailureKind.ACTIVATION_FAILED, failed.kind)
        assertEquals(good.datasetId, resolve().datasetId)
    }

    // ---- cancellation and concurrency ----

    @Test
    fun `cancelling before the download starts changes nothing`() {
        newRoot()
        resolve()
        serveV2()
        val result = updater().update(settings, isCancelled = { true })
        assertEquals(GeoUpdateFailureKind.CANCELLED, (result as GeoUpdateResult.Failed).kind)
        assertStillOnBundled()
        assertTrue(http.requested.isEmpty())
    }

    @Test
    fun `cancelling after the first file keeps the previous databases and cleans the temp area`() {
        newRoot()
        resolve()
        serveV2()
        var progressEvents = 0
        val result = updater().update(settings, isCancelled = { progressEvents >= 2 }) { progressEvents++ }
        assertEquals(GeoUpdateFailureKind.CANCELLED, (result as GeoUpdateResult.Failed).kind)
        assertStillOnBundled()
        assertFalse(File(root, GeoDataUpdater.TEMP_NAME).exists())
    }

    @Test
    fun `a second concurrent update is refused and changes nothing`() {
        newRoot()
        root.mkdirs()
        serveV2()
        FileChannel.open(File(root, GeoDataUpdater.LOCK_NAME).toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
            val held = channel.tryLock()
            assertNotNull(held)
            val result = updater().update(settings)
            assertEquals(GeoUpdateFailureKind.BUSY, (result as GeoUpdateResult.Failed).kind)
            held!!.release()
        }
        assertTrue(http.requested.isEmpty())
        assertTrue(updater().update(settings) is GeoUpdateResult.Updated)
    }

    private fun assertNotNull(value: Any?) = assertTrue(value != null)

    // ---- damaged state falls back to bundled ----

    @Test
    fun `a damaged active dataset degrades to the bundled databases instead of no databases`() {
        newRoot()
        serveV2()
        val good = updater().update(settings) as GeoUpdateResult.Updated
        val dir = File(root, "geo-${good.datasetId}")
        File(dir, "geoip.dat").writeBytes(GeoTestData.geoipV2.copyOf(20))
        val r = resolve()
        assertEquals(GeoDataOrigin.BUNDLED, r.origin)
        assertTrue(updater().status().activePointerBroken)
        assertArrayEquals(GeoTestData.geoipV1, File(r.directory, "geoip.dat").readBytes())
    }

    @Test
    fun `a pointer to a missing dataset or a corrupt pointer degrades to bundled`() {
        newRoot()
        resolve()
        File(root, GeoActiveDataset.POINTER_NAME).writeText("""{"schema":1,"active":"0123456789abcdef","previous":"","activatedAtMillis":5}""")
        assertEquals(GeoDataOrigin.BUNDLED, resolve().origin)
        File(root, GeoActiveDataset.POINTER_NAME).writeText("not json at all")
        assertEquals(GeoDataOrigin.BUNDLED, resolve().origin)
        File(root, GeoActiveDataset.POINTER_NAME).writeText("""{"schema":1,"active":"../../etc","previous":"","activatedAtMillis":5}""")
        assertEquals(GeoDataOrigin.BUNDLED, resolve().origin)
    }

    @Test
    fun `an active dataset with a forged marker id is not trusted`() {
        newRoot()
        serveV2()
        val good = updater().update(settings) as GeoUpdateResult.Updated
        val dir = File(root, "geo-${good.datasetId}")
        val marker = File(dir, GeoDataStager.MARKER_NAME)
        marker.writeText(marker.readText().replace(good.datasetId, "ffffffffffffffff"))
        assertEquals(GeoDataOrigin.BUNDLED, resolve().origin)
    }

    // ---- pruning and reset ----

    @Test
    fun `older downloaded datasets are pruned but the active and the previous one are kept`() {
        newRoot()
        val ids = mutableListOf<String>()
        for (n in 1..3) {
            http.serve(ipUrl, GeoTestData.geoip("CN", "N$n"))
            http.serve(siteUrl, GeoTestData.geosite("GOOGLE", "N$n"))
            ids += (updater().update(settings) as GeoUpdateResult.Updated).datasetId
        }
        val bundledId = resolveBundledIdAfterFallback()
        val dirs = geoDirs()
        assertFalse("oldest download is pruned", "geo-${ids[0]}" in dirs)
        assertTrue("previous is kept for rollback", "geo-${ids[1]}" in dirs)
        assertTrue("active is kept", "geo-${ids[2]}" in dirs)
        assertEquals(ids[2], GeoActiveDataset.readPointer(root)!!.active)
        assertEquals(ids[1], GeoActiveDataset.readPointer(root)!!.previous)
        assertNotEquals(bundledId, ids[2])
    }

    @Test
    fun `the dataset a running core was started with is never pruned by later updates`() {
        newRoot()
        http.serve(ipUrl, GeoTestData.geoip("CN", "N1"))
        http.serve(siteUrl, GeoTestData.geosite("GOOGLE", "N1"))
        val first = updater().update(settings) as GeoUpdateResult.Updated
        // the :xray process starts its core on the first dataset and records that
        val provider = GeoAssetDirProvider(root, bundled)
        assertEquals(first.datasetId, provider.resolveInitial().datasetId)
        // two further updates happen while that core keeps running
        for (n in 2..3) {
            http.serve(ipUrl, GeoTestData.geoip("CN", "N$n"))
            http.serve(siteUrl, GeoTestData.geosite("GOOGLE", "N$n"))
            updater().update(settings)
        }
        assertTrue("the directory the running core uses must still exist", File(root, "geo-${first.datasetId}").isDirectory)
        assertTrue(GeoActiveDataset.inspect(File(root, "geo-${first.datasetId}")) != null)
        // resetting to bundled does not remove it either
        assertTrue(updater().resetToBundled())
        assertTrue(File(root, "geo-${first.datasetId}").isDirectory)
    }

    private fun resolveBundledIdAfterFallback(): String {
        // clear pointer temporarily is not allowed here; compute bundled id from a separate root
        val other = File(tmp.newFolder("other${System.nanoTime()}"), "xray-assets")
        return GeoDataBootstrap.resolve(other, bundled).datasetId!!
    }

    @Test
    fun `prune never touches the bundled dataset, quarantine, foreign directories or files`() {
        newRoot()
        val bundledDir = resolve().directory
        val foreign = File(root, "geo-aaaaaaaaaaaaaaaa").apply { mkdirs() }
        File(foreign, "note.txt").writeText("mine")
        val quarantine = File(root, "geo-bbbbbbbbbbbbbbbb.quarantine-1").apply { mkdirs() }
        File(quarantine, "geoip.dat").writeText("evidence")
        File(root, "geo-cccccccccccccccc").writeText("a file named like a dataset")
        serveV2()
        updater().update(settings)
        assertTrue(bundledDir.isDirectory)
        assertEquals("mine", File(foreign, "note.txt").readText())
        assertEquals("evidence", File(quarantine, "geoip.dat").readText())
        assertTrue(File(root, "geo-cccccccccccccccc").isFile)
    }

    @Test
    fun `resetting returns to the bundled databases and keeps the old download until the next update`() {
        newRoot()
        serveV2()
        val good = updater().update(settings) as GeoUpdateResult.Updated
        assertTrue(updater().resetToBundled())
        val r = resolve()
        assertEquals(GeoDataOrigin.BUNDLED, r.origin)
        assertNull(GeoActiveDataset.readPointer(root))
        assertTrue("a running core may still read it", File(root, "geo-${good.datasetId}").isDirectory)
        assertEquals(GeoDataOrigin.BUNDLED, updater().status().origin)
    }

    // ---- what the VPN core process picks up ----

    @Test
    fun `the core provider picks up a newly activated dataset only when asked after the pointer changed`() {
        newRoot()
        val provider = GeoAssetDirProvider(root, bundled)
        val first = provider.resolveInitial()
        assertEquals(GeoDataOrigin.BUNDLED, first.origin)
        assertEquals(first.datasetId, GeoAssetDirProvider.readEffectiveId(root))
        assertNull("nothing changed yet", provider.changedResolution())

        serveV2()
        val updated = updater().update(settings) as GeoUpdateResult.Updated
        val changed = provider.changedResolution()!!
        assertEquals(GeoDataOrigin.DOWNLOADED, changed.origin)
        assertEquals(updated.datasetId, changed.datasetId)
        assertEquals(updated.datasetId, GeoAssetDirProvider.readEffectiveId(root))
        assertEquals(updated.datasetId, updater().status().coreDatasetId)
        assertNull("asking again without a change is a no-op", provider.changedResolution())
    }

    @Test
    fun `a failed update never changes what the core provider returns`() {
        newRoot()
        val provider = GeoAssetDirProvider(root, bundled)
        val first = provider.resolveInitial()
        http.status(ipUrl, 503)
        http.status(siteUrl, 503)
        updater().update(settings)
        assertNull(provider.changedResolution())
        assertEquals(first.directory, GeoDataBootstrap.resolve(root, bundled).directory)
    }
}
