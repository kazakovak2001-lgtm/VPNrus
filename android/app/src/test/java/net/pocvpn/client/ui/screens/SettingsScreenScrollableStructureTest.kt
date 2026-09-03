package net.pocvpn.client.ui.screens

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B30A - physical-validation fix. This project has no Compose UI test
 * harness (androidx.compose.ui:ui-test-junit4/ui-test-manifest are not
 * project dependencies - see AppRootInstalledAppsLoadingTest's own docs for
 * the same constraint), so a real composition/semantics-tree assertion
 * isn't available here. This is the "at minimum, prove structurally" fallback:
 * a source-level guard that SettingsScreen's root content is wrapped in a
 * scrollable container, so a future edit can't silently drop verticalScroll
 * and reintroduce the exact bug found during physical validation (the B29
 * Diagnostics export/clear buttons composed below the visible viewport with
 * no way to reach them - see SettingsScreen's own docs on the fix).
 */
class SettingsScreenScrollableStructureTest {

    @Test
    fun `SettingsScreen root Column is wrapped in verticalScroll`() {
        val source = settingsScreenSource()
        assertTrue(
            "SettingsScreen.kt must apply Modifier.verticalScroll(...) to its root Column " +
                "so the Smart Connect / Diagnostics sections remain reachable on real devices",
            Regex("""Column\s*\(.*?verticalScroll\(""", RegexOption.DOT_MATCHES_ALL).containsMatchIn(source),
        )
    }

    private fun settingsScreenSource(): String {
        val candidates = listOf(
            File("src/main/java/net/pocvpn/client/ui/screens/SettingsScreen.kt"),
            File("android/app/src/main/java/net/pocvpn/client/ui/screens/SettingsScreen.kt"),
        )
        val file = candidates.firstOrNull { it.exists() }
            ?: error("SettingsScreen.kt not found from working dir ${File(".").absolutePath} - tried $candidates")
        return file.readText()
    }
}
