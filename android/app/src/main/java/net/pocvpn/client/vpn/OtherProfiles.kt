package net.pocvpn.client.vpn

import android.content.Context
import android.os.Process
import android.os.UserManager

/**
 * Android scopes a VpnService to the user that started it (plus that user's
 * restricted profiles): apps in a clone profile (OEM "Dual apps"/MultiApp,
 * Android 14 `profile.CLONE`), a work profile or any other user keep going
 * direct while Nova shows Protected, and no VpnService API can add them
 * (measured on OPPO CPH2173, B57 C6-R2). Nova cannot close that gap; it can
 * only say so.
 */
object OtherProfiles {
    /**
     * Profiles of this user other than itself (clone, work), or null when
     * Android does not answer. Separate full users (guest, OEM second space)
     * are not visible here - the static Settings note covers them.
     */
    fun count(context: Context): Int? = try {
        val userManager = context.getSystemService(UserManager::class.java)
        val me = Process.myUserHandle()
        userManager?.userProfiles?.count { it != me }
    } catch (e: Exception) {
        null
    }
}
