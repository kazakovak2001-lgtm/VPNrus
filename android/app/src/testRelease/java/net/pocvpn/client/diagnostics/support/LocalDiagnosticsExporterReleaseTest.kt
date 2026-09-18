package net.pocvpn.client.diagnostics.support

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * SG-002 evidence-closure - runs ONLY under `testReleaseUnitTest` (this
 * file lives in `src/testRelease`, AGP's per-build-type unit test source
 * set), against the RELEASE build type's own compiled
 * `LocalDiagnosticsExporter` (`src/release/.../LocalDiagnosticsExporter
 * .kt`) - genuinely a different class body than the debug implementation
 * this same test file's sibling ([LocalDiagnosticsExporterTest], under
 * `src/testDebug`) exercises; AGP never compiles both bodies into the
 * same build. Proves the functional property the release build must
 * have: calling this symbol writes NOTHING and returns null, regardless
 * of what JSON it is given - i.e. a release build has no callable local
 * support-diagnostics exporter, verified by actually calling it (not
 * merely by trusting `BuildConfig.DEBUG` reachability).
 */
class LocalDiagnosticsExporterReleaseTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun `exportLatest returns null and writes nothing in a release build`() {
        val filesDir = tempFolder.newFolder("files")

        val result = LocalDiagnosticsExporter.exportLatest(filesDir, """{"schemaVersion":1,"sessions":[]}""")

        assertNull("the release stub must never return a written File", result)
        assertFalse(
            "the release stub must never create the support-diagnostics directory at all",
            java.io.File(filesDir, "support-diagnostics").exists(),
        )
    }
}
