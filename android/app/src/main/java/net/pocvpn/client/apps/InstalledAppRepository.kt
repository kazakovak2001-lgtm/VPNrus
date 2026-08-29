package net.pocvpn.client.apps

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap

/** One selectable row in the split-tunneling app picker. */
data class InstalledAppInfo(
    val packageName: String,
    val label: String,
    val icon: ImageBitmap?,
)

interface InstalledAppRepository {
    /** Launchable user-facing apps on this device, Nova VPN itself excluded, sorted by label. */
    fun listLaunchableApps(): List<InstalledAppInfo>
}

/**
 * B8H - enumerates apps the SAME way a home-screen launcher would: apps that
 * respond to ACTION_MAIN/CATEGORY_LAUNCHER. Deliberately NOT
 * PackageManager.getInstalledApplications(), which would need the
 * QUERY_ALL_PACKAGES permission (Play policy-restricted, and far broader
 * than this screen needs - background services, libraries, etc. the user
 * would never think of as "an app" to route). The AndroidManifest.xml
 * <queries> block declaring this exact ACTION_MAIN/CATEGORY_LAUNCHER intent
 * is what makes queryIntentActivities see other apps at all under Android
 * 11+'s package-visibility filtering, without QUERY_ALL_PACKAGES.
 */
class PackageManagerInstalledAppRepository(
    private val context: Context,
) : InstalledAppRepository {

    private val selfPackageName: String = context.packageName

    override fun listLaunchableApps(): List<InstalledAppInfo> {
        val pm = context.packageManager
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = try {
            pm.queryIntentActivities(launcherIntent, 0)
        } catch (e: Exception) {
            emptyList()
        }

        return resolved
            .mapNotNull { it.activityInfo?.packageName }
            .distinct()
            .filter { it != selfPackageName }
            .mapNotNull { packageName -> toAppInfoOrNull(pm, packageName) }
            .sortedBy { it.label.lowercase() }
    }

    // A package resolved a moment ago by queryIntentActivities can still
    // vanish (uninstalled concurrently) before this runs - handled the same
    // "safely ignore" way as a stale saved selection (see
    // AppRoutingLists' own docs), never a crash here either.
    private fun toAppInfoOrNull(pm: PackageManager, packageName: String): InstalledAppInfo? {
        val appInfo = try {
            pm.getApplicationInfo(packageName, 0)
        } catch (e: PackageManager.NameNotFoundException) {
            return null
        }
        val label = try {
            pm.getApplicationLabel(appInfo).toString()
        } catch (e: Exception) {
            null
        }?.takeIf { it.isNotBlank() } ?: packageName
        val icon = try {
            pm.getApplicationIcon(appInfo).toBitmap().asImageBitmap()
        } catch (e: Exception) {
            null
        }
        return InstalledAppInfo(packageName = packageName, label = label, icon = icon)
    }
}
