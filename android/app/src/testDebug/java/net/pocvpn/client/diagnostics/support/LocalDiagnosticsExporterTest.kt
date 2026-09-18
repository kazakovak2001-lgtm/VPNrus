package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * SG-002 evidence-closure - runs ONLY under `testDebugUnitTest` (this file
 * lives in `src/testDebug`, AGP's per-build-type unit test source set),
 * against the REAL debug-build implementation of
 * [LocalDiagnosticsExporter] (`src/debug/.../LocalDiagnosticsExporter.kt`)
 * - never the release no-op stub, which has its own separate test under
 * `src/testRelease` (see [LocalDiagnosticsExporterReleaseTest]). Proves
 * this object is a pure, lossless local write of whatever JSON it is
 * given: it must never mutate, re-derive, or re-sanitize a single
 * character of the bundle [MainViewModel.exportSupportBundleJson]/
 * [buildSupportBundle]/[SupportBundle.toJson] already produced.
 */
class LocalDiagnosticsExporterTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `exportLatest writes the given json verbatim, byte for byte, and returns the file`() {
        val filesDir = tempFolder.newFolder("files")
        val json = """{"schemaVersion":1,"sessions":[]}"""

        val file = LocalDiagnosticsExporter.exportLatest(filesDir, json)

        assertNotNull("the debug implementation must actually write and return a File", file)
        assertEquals(json, file!!.readText())
    }

    @Test
    fun `exportLatest never mutates a real support bundle produced by the unmodified production path`() {
        val store = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(store, appVersionName = "1.2.3", appVersionCode = 42L)
        recorder.startSession(
            SupportDiagnosticsRecorder.StartContext(
                networkType = NetworkType.WIFI,
                networkValidatedInternet = true,
                networkCaptivePortal = false,
                networkIpv4Available = true,
                networkIpv6Available = false,
                networkFingerprintId = "abc123fingerprint",
                rawRestrictionClass = RestrictionClass.UNKNOWN,
                stabilizedRestrictionClass = RestrictionClass.UNKNOWN,
                routingMode = RoutingMode.FULL_VPN,
                gatewaySelectionMode = GatewaySelectionMode.AUTO,
            ),
        )
        recorder.recordCandidateAttemptStarted(
            PathKind.DIRECT,
            TransportKind.XRAY_XHTTP,
            AttemptEndpointIdentity.Direct(EndpointId("frankfurt")),
        )
        recorder.recordTransportAttemptStarted(EndpointId("frankfurt"), TransportKind.XRAY_XHTTP)
        recorder.recordEndpointReachabilityResult(ReachabilityState.REACHABLE)
        recorder.recordTransportStart(TransportKind.XRAY_XHTTP)
        recorder.recordTransportHandshakeResult(success = true)
        recorder.finishProtected()

        // The SAME production call MainViewModel.exportSupportBundleJson()
        // makes: buildSupportBundle(...).toJson() - never a second/divergent
        // serialization written just for this test.
        val expectedJson = buildSupportBundle(
            sessions = store.recent(),
            appVersionName = "1.2.3",
            appVersionCode = 42L,
            nowEpochMillis = 1_000_000L,
        ).toJson()

        val filesDir = tempFolder.newFolder("files")
        val file = LocalDiagnosticsExporter.exportLatest(filesDir, expectedJson)

        assertEquals("the exporter must not alter a single byte of the real bundle", expectedJson, file!!.readText())
        assertTrue(expectedJson.contains("\"attemptedEndpointId\":\"frankfurt\""))
        assertTrue(expectedJson.contains("\"plannedEndpointId\":\"frankfurt\""))
    }

    @Test
    fun `exportLatest overwrites the previous export rather than appending or corrupting it`() {
        val filesDir = tempFolder.newFolder("files")

        val first = LocalDiagnosticsExporter.exportLatest(filesDir, """{"n":1}""")
        val second = LocalDiagnosticsExporter.exportLatest(filesDir, """{"n":2}""")

        assertEquals(first!!.absolutePath, second!!.absolutePath)
        assertEquals("""{"n":2}""", second.readText())
    }

    @Test
    fun `exportLatest stores the file under app-private storage, never a shared or public location`() {
        val filesDir = tempFolder.newFolder("files")

        val file = LocalDiagnosticsExporter.exportLatest(filesDir, "{}")

        assertTrue(
            "must be written under the given app-private filesDir, not a shared/external location",
            file!!.absolutePath.startsWith(filesDir.absolutePath),
        )
        assertFalse(file.absolutePath.contains("Download"))
        assertFalse(file.absolutePath.contains("external"))
    }
}
