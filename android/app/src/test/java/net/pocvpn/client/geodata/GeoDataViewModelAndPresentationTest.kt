package net.pocvpn.client.geodata

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.vpn.xray.GeoDataOrigin
import net.pocvpn.client.vpn.xray.GeoFileInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class GeoDataViewModelAndPresentationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val ipUrl = "https://one.example.org/geoip.dat"
    private val siteUrl = "https://two.example.net/geosite.dat"

    private class Env(val store: GeoDataSettingsStore, val http: FakeHttp, val root: File)

    private fun env(store: GeoDataSettingsStore = InMemoryGeoDataSettingsStore()): Env =
        Env(store, FakeHttp(), File(tmp.newFolder("nb${System.nanoTime()}"), "xray-assets"))

    private fun TestScope.vm(env: Env): GeoDataViewModel {
        val updater = GeoDataUpdater(env.root, FakeBundled(), GeoDatabaseDownloader(env.http))
        return GeoDataViewModel(env.store, updater, UnconfinedTestDispatcher(testScheduler), this)
    }

    // ---- view model: saving ----

    @Test
    fun `inputs start from the saved settings`() = runTest {
        val e = env(InMemoryGeoDataSettingsStore(GeoDataSettings(ipUrl, siteUrl)))
        val s = vm(e).state.value
        assertEquals(ipUrl, s.geoipInput)
        assertEquals(siteUrl, s.geositeInput)
        assertFalse(s.hasUnsavedChanges)
    }

    @Test
    fun `saving stores both urls separately and normalizes them`() = runTest {
        val e = env()
        val model = vm(e)
        model.onGeoipInputChanged("  $ipUrl ")
        model.onGeositeInputChanged(siteUrl)
        assertTrue(model.state.value.hasUnsavedChanges)
        assertTrue(model.save())
        assertEquals(GeoDataSettings(ipUrl, siteUrl), e.store.read())
        assertFalse(model.state.value.hasUnsavedChanges)
        assertEquals(ipUrl, model.state.value.geoipInput)
    }

    @Test
    fun `an invalid url is not saved and the field shows why`() = runTest {
        val e = env(InMemoryGeoDataSettingsStore(GeoDataSettings(ipUrl, "")))
        val model = vm(e)
        model.onGeoipInputChanged("http://insecure.example/geoip.dat")
        model.onGeositeInputChanged(siteUrl)
        assertFalse(model.save())
        assertEquals(GeoUrlProblem.NOT_HTTPS, model.state.value.geoipProblem)
        assertNull(model.state.value.geositeProblem)
        assertEquals("nothing was written", GeoDataSettings(ipUrl, ""), e.store.read())
        // editing the field clears its error
        model.onGeoipInputChanged(ipUrl)
        assertNull(model.state.value.geoipProblem)
    }

    @Test
    fun `clearing a field removes that url`() = runTest {
        val e = env(InMemoryGeoDataSettingsStore(GeoDataSettings(ipUrl, siteUrl)))
        val model = vm(e)
        model.onGeositeInputChanged("")
        assertTrue(model.save())
        assertEquals(GeoDataSettings(ipUrl, ""), e.store.read())
    }

    @Test
    fun `a storage failure is reported and keeps the unsaved input`() = runTest {
        val failing = object : GeoDataSettingsStore {
            override fun read() = GeoDataSettings()
            override fun write(settings: GeoDataSettings) = throw IOException("disk full")
        }
        val model = vm(env(failing))
        model.onGeoipInputChanged(ipUrl)
        assertFalse(model.save())
        assertTrue(model.state.value.saveFailed)
        assertEquals(ipUrl, model.state.value.geoipInput)
    }

    // ---- view model: update flow ----

    @Test
    fun `refreshing the status shows the bundled databases at first`() = runTest {
        val model = vm(env())
        model.refreshStatus()
        advanceUntilIdle()
        assertEquals(GeoDataOrigin.BUNDLED, model.state.value.status!!.origin)
    }

    @Test
    fun `a manual update saves the inputs downloads activates and shows the result`() = runTest {
        val e = env()
        e.http.serve(ipUrl, GeoTestData.geoipV2)
        e.http.serve(siteUrl, GeoTestData.geositeV2)
        val model = vm(e)
        model.onGeoipInputChanged(ipUrl)
        model.onGeositeInputChanged(siteUrl)
        model.startUpdate()
        advanceUntilIdle()
        val s = model.state.value
        assertEquals(GeoDataSettings(ipUrl, siteUrl), e.store.read())
        val finished = s.operation as GeoOperationState.Finished
        assertTrue(finished.result is GeoUpdateResult.Updated)
        assertEquals(GeoDataOrigin.DOWNLOADED, s.status!!.origin)
        assertFalse(s.isRunning)
    }

    @Test
    fun `a failed update shows a readable error and keeps the previous databases`() = runTest {
        val e = env()
        e.http.status(ipUrl, 404)
        val model = vm(e)
        model.onGeoipInputChanged(ipUrl)
        model.startUpdate()
        advanceUntilIdle()
        val s = model.state.value
        val failed = (s.operation as GeoOperationState.Finished).result as GeoUpdateResult.Failed
        assertEquals(GeoUpdateFailureKind.DOWNLOAD_FAILED, failed.kind)
        assertEquals(GeoDataOrigin.BUNDLED, s.status!!.origin)
        val text = GeoDataPresentation.describeFailure(failed)
        assertTrue(text, text.contains("HTTP 404"))
        assertTrue(text, text.contains("previous databases are unchanged"))
    }

    @Test
    fun `an update without any url explains what to do and does not touch the network`() = runTest {
        val e = env()
        val model = vm(e)
        model.startUpdate()
        advanceUntilIdle()
        val failed = (model.state.value.operation as GeoOperationState.Finished).result as GeoUpdateResult.Failed
        assertEquals(GeoUpdateFailureKind.NOT_CONFIGURED, failed.kind)
        assertTrue(e.http.requested.isEmpty())
    }

    @Test
    fun `an invalid url blocks the update before saving or downloading`() = runTest {
        val e = env()
        val model = vm(e)
        model.onGeoipInputChanged("ftp://example.org/geoip.dat")
        model.startUpdate()
        advanceUntilIdle()
        assertEquals(GeoOperationState.Idle, model.state.value.operation)
        assertEquals(GeoUrlProblem.NOT_HTTPS, model.state.value.geoipProblem)
        assertTrue(e.http.requested.isEmpty())
    }

    @Test
    fun `cancelling a running update ends it without activating anything`() = runTest {
        val e = env()
        lateinit var model: GeoDataViewModel
        // The transport asks to cancel while the download is in progress.
        e.http.handlers[ipUrl] = {
            model.cancelUpdate()
            GeoHttpResponse(200, null, null, GeoTestData.geoipV2.size.toLong(), java.io.ByteArrayInputStream(GeoTestData.geoipV2))
        }
        model = vm(e)
        model.onGeoipInputChanged(ipUrl)
        model.startUpdate()
        advanceUntilIdle()
        val finished = model.state.value.operation as GeoOperationState.Finished
        assertEquals(GeoUpdateFailureKind.CANCELLED, (finished.result as GeoUpdateResult.Failed).kind)
        assertEquals(GeoDataOrigin.BUNDLED, model.state.value.status!!.origin)
        assertTrue(GeoDataPresentation.describeFailure(finished.result as GeoUpdateResult.Failed).contains("cancelled"))
    }

    @Test
    fun `using the built-in databases after an update goes back to bundled`() = runTest {
        val e = env()
        e.http.serve(ipUrl, GeoTestData.geoipV2)
        val model = vm(e)
        model.onGeoipInputChanged(ipUrl)
        model.startUpdate()
        advanceUntilIdle()
        assertEquals(GeoDataOrigin.DOWNLOADED, model.state.value.status!!.origin)
        model.useBundled()
        advanceUntilIdle()
        assertEquals(GeoDataOrigin.BUNDLED, model.state.value.status!!.origin)
        assertTrue((model.state.value.operation as GeoOperationState.Info).message.contains("built-in"))
    }

    // ---- presentation ----

    @Test
    fun `url problems have distinct readable messages`() {
        val messages = GeoUrlProblem.entries.map { GeoDataPresentation.describeUrlProblem(it) }
        assertEquals(messages.size, messages.toSet().size)
        assertTrue(GeoDataPresentation.describeUrlProblem(GeoUrlProblem.NOT_HTTPS).contains("https://"))
    }

    @Test
    fun `every download failure produces a message that names the file and keeps the old databases`() {
        for (kind in GeoDownloadFailure.entries) {
            val failure = GeoUpdateResult.Failed(
                GeoUpdateFailureKind.DOWNLOAD_FAILED,
                file = GeoDatabaseKind.GEOSITE,
                download = kind,
                httpStatus = 503,
                invalidReason = GeoInvalidReason.NOT_A_DATABASE,
            )
            val text = GeoDataPresentation.describeFailure(failure)
            assertTrue("$kind: $text", text.startsWith("geosite.dat: "))
            assertTrue("$kind: $text", text.contains("previous databases are unchanged"))
        }
    }

    @Test
    fun `failure messages never contain the address that was used`() {
        val secretHost = "private-host.example.org"
        val failure = GeoUpdateResult.Failed(GeoUpdateFailureKind.DOWNLOAD_FAILED, GeoDatabaseKind.GEOIP, GeoDownloadFailure.NETWORK, detail = "The server could not be reached.")
        assertFalse(GeoDataPresentation.describeFailure(failure).contains(secretHost))
        assertFalse(GeoDataPresentation.describeFailure(failure).contains("http"))
    }

    @Test
    fun `html and swapped files get specific explanations`() {
        fun text(reason: GeoInvalidReason) = GeoDataPresentation.describeFailure(
            GeoUpdateResult.Failed(GeoUpdateFailureKind.DOWNLOAD_FAILED, GeoDatabaseKind.GEOIP, GeoDownloadFailure.NOT_A_DATABASE, invalidReason = reason),
        )
        assertTrue(text(GeoInvalidReason.LOOKS_LIKE_HTML).contains("web page"))
        assertTrue(text(GeoInvalidReason.WRONG_KIND).contains("swapped"))
    }

    @Test
    fun `progress text and fraction`() {
        val unknown = GeoProgress(GeoUpdatePhase.DOWNLOADING, GeoDatabaseKind.GEOIP, 2_097_152L, -1L)
        assertEquals("Downloading geoip.dat: 2.0 MB", GeoDataPresentation.describeProgress(unknown))
        assertNull(GeoDataPresentation.progressFraction(unknown))
        val known = GeoProgress(GeoUpdatePhase.DOWNLOADING, GeoDatabaseKind.GEOSITE, 1_048_576L, 4_194_304L)
        assertEquals("Downloading geosite.dat: 1.0 MB of 4.0 MB", GeoDataPresentation.describeProgress(known))
        assertEquals(0.25f, GeoDataPresentation.progressFraction(known)!!, 0.0001f)
        assertEquals("Downloading geoip.dat...", GeoDataPresentation.describeProgress(GeoProgress(GeoUpdatePhase.DOWNLOADING, GeoDatabaseKind.GEOIP)))
        assertNull(GeoDataPresentation.progressFraction(GeoProgress(GeoUpdatePhase.STAGING, null, 5, 10)))
    }

    @Test
    fun `status lines say which databases are in use and whether the core has them`() {
        val files = listOf(GeoFileInfo("geoip.dat", 18_534_419L, "7806115947f8"), GeoFileInfo("geosite.dat", 8_659_692L, "725397e93d00"))
        val bundled = GeoDataStatus(GeoDataOrigin.BUNDLED, "aaaaaaaaaaaaaaaa", files, null, false, null)
        assertEquals("Built-in databases", GeoDataPresentation.describeOrigin(bundled))
        assertEquals("geoip.dat - 17.7 MB - 78061159", GeoDataPresentation.describeFile(files[0]))
        assertTrue(GeoDataPresentation.describeCoreUsage(bundled)!!.startsWith("Not used by the VPN core yet"))

        val broken = bundled.copy(activePointerBroken = true)
        assertTrue(GeoDataPresentation.describeOrigin(broken).contains("not usable"))

        val downloaded = bundled.copy(origin = GeoDataOrigin.DOWNLOADED, activatedAtMillis = 1_700_000_000_000L, coreDatasetId = "aaaaaaaaaaaaaaaa")
        assertTrue(GeoDataPresentation.describeOrigin(downloaded).startsWith("Downloaded databases (activated"))
        assertEquals("Handed to the VPN core at its last start.", GeoDataPresentation.describeCoreUsage(downloaded))
        val behind = downloaded.copy(coreDatasetId = "bbbbbbbbbbbbbbbb")
        assertTrue(GeoDataPresentation.describeCoreUsage(behind)!!.contains("last started with the previous"))
        assertNull(GeoDataPresentation.describeCoreUsage(bundled.copy(datasetId = null)))
        assertNotNull(GeoDataPresentation.RESTART_NOTICE)
        assertTrue(GeoDataPresentation.RESTART_NOTICE.contains("already running"))
    }

    @Test
    fun `the screen tells the user that downloads bypass the vpn tunnel`() {
        assertTrue(GeoDataPresentation.OUTSIDE_VPN_NOTICE.contains("outside the VPN"))
        assertFalse(GeoDataPresentation.OUTSIDE_VPN_NOTICE.contains("http"))
    }

    @Test
    fun `byte formatting`() {
        assertEquals("512 B", GeoDataPresentation.formatBytes(512))
        assertEquals("1.5 KB", GeoDataPresentation.formatBytes(1536))
        assertEquals("8.3 MB", GeoDataPresentation.formatBytes(8_659_692L))
    }
}
