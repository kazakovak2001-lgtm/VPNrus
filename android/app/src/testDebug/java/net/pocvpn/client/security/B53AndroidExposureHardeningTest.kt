package net.pocvpn.client.security

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Source-boundary regression checks for B53's artifact-oriented hardening. */
class B53AndroidExposureHardeningTest {

    @Test
    fun `main manifest denies backup and declares both backup rule generations`() {
        val manifest = projectFile("src/main/AndroidManifest.xml").readText()

        assertTrue(manifest.contains("android:allowBackup=\"false\""))
        assertTrue(manifest.contains("android:fullBackupContent=\"@xml/backup_rules\""))
        assertTrue(manifest.contains("android:dataExtractionRules=\"@xml/data_extraction_rules\""))

        val legacy = projectFile("src/main/res/xml/backup_rules.xml").readText()
        val modern = projectFile("src/main/res/xml/data_extraction_rules.xml").readText()
        assertTrue(legacy.contains("<exclude domain=\"root\" path=\".\""))
        assertTrue(modern.contains("<cloud-backup>"))
        assertTrue(modern.contains("<device-transfer>"))
        assertFalse(modern.contains("<include"))
    }

    @Test
    fun `debug Xray profile import requires shell protected component permission`() {
        val manifest = projectFile("src/debug/AndroidManifest.xml").readText()
        val activityStart = manifest.indexOf("net.pocvpn.client.debug.XrayDiagnosticsActivity")
        val activityEnd = manifest.indexOf("/>", activityStart)
        val declaration = manifest.substring(activityStart, activityEnd)

        assertTrue(declaration.contains("android:exported=\"true\""))
        assertTrue(declaration.contains("android:permission=\"android.permission.DUMP\""))
    }

    @Test
    fun `production Shadowsocks process output is drained without logcat forwarding`() {
        val launcher = projectFile(
            "src/main/java/net/pocvpn/client/vpn/shadowsocks/ShadowsocksProcessLauncher.kt",
        ).readText()

        assertTrue(launcher.contains("forEachLine { /* drain without logging */ }"))
        assertFalse(launcher.contains("android.util.Log"))
        assertFalse(launcher.contains("Log.d("))
    }

    private fun projectFile(relativePath: String): File = File(relativePath).also {
        check(it.isFile) { "Expected app-module file at ${it.absolutePath}" }
    }
}
