package net.pocvpn.client.vpn.policy

import android.content.Context
import android.content.pm.PackageManager

/**
 * B8H - the ONLY thing VpnController needs to know about installed apps:
 * whether one specific package is still present. A `fun interface` (not a
 * direct PackageManager dependency) so resolveAppRoutingLists' caller stays
 * unit-testable on the JVM with a plain lambda - see
 * VpnControllerSplitTunnelingTest's FakeInstalledPackageChecker.
 */
fun interface InstalledPackageChecker {
    fun isInstalled(packageName: String): Boolean

    companion object {
        /** Every package name is treated as installed - pairs with AppRoutingPolicyStore.allApps() as the safe no-op default. */
        fun alwaysInstalled(): InstalledPackageChecker = InstalledPackageChecker { true }
    }
}

/**
 * getApplicationInfo() throwing NameNotFoundException for a since-uninstalled
 * package is the ONLY signal used here - matches exactly what
 * resolveAppRoutingLists' "stale/uninstalled package does not crash"
 * requirement is guarding against (see GoBackend.setStateInternal's own
 * bytecode: it has no such guard itself - see AppRoutingLists' own docs).
 */
class AndroidInstalledPackageChecker(private val context: Context) : InstalledPackageChecker {
    override fun isInstalled(packageName: String): Boolean =
        try {
            context.packageManager.getApplicationInfo(packageName, 0)
            true
        } catch (e: PackageManager.NameNotFoundException) {
            false
        }
}
