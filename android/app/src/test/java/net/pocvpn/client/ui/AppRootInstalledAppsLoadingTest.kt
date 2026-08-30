package net.pocvpn.client.ui

import kotlinx.coroutines.test.runTest
import net.pocvpn.client.apps.InstalledAppInfo
import net.pocvpn.client.apps.InstalledAppRepository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Startup-performance regression guard: PackageManagerInstalledAppRepository's
 * synchronous scan (queryIntentActivities/getApplicationInfo/Label/Icon +
 * sorting) must never run on the caller's thread - see AppRoot's own
 * loadInstalledApps docs. This proves the dispatcher switch actually happens
 * and the repository's result is returned unchanged, without needing a
 * Compose test dependency (this project has none) to exercise the
 * lazy-load-on-AppSelector-open/cache-for-AppRoot-lifetime behavior itself.
 */
class AppRootInstalledAppsLoadingTest {

    private class RecordingInstalledAppRepository(
        private val result: List<InstalledAppInfo>,
    ) : InstalledAppRepository {
        var callCount = 0
            private set
        var lastCallThreadName: String? = null
            private set

        override fun listLaunchableApps(): List<InstalledAppInfo> {
            callCount++
            lastCallThreadName = Thread.currentThread().name
            return result
        }
    }

    @Test
    fun `loadInstalledApps returns exactly what the repository provides`() = runTest {
        val apps = listOf(
            InstalledAppInfo(packageName = "com.example.a", label = "A", icon = null),
            InstalledAppInfo(packageName = "com.example.b", label = "B", icon = null),
        )
        val repository = RecordingInstalledAppRepository(apps)

        val result = loadInstalledApps(repository)

        assertEquals(apps, result)
        assertEquals(1, repository.callCount)
    }

    @Test
    fun `loadInstalledApps runs the repository scan off the calling thread`() = runTest {
        val callingThreadName = Thread.currentThread().name
        val repository = RecordingInstalledAppRepository(emptyList())

        loadInstalledApps(repository)

        assertNotEquals(callingThreadName, repository.lastCallThreadName)
    }
}
