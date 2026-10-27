package net.pocvpn.client.vpn.protection

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import java.net.Inet6Address

/**
 * Reads this app's VPN network from the system for [TunnelProtectionCheck].
 * Works for every transport: the AWG service, `:xray` and the Hysteria2
 * service all run under this app's UID, so the VPN network is ours even
 * when the Nova app itself is excluded from the Xray tunnel (the check reads
 * the network's properties, it sends no traffic). Returns null when no VPN
 * network is visible yet.
 */
class AndroidTunnelLinkReader(context: Context) {
    private val connectivity = context.applicationContext.getSystemService(ConnectivityManager::class.java)

    @Suppress("DEPRECATION") // allNetworks: the only enumeration that works on API 26-30.
    fun read(): TunnelLinkSnapshot? {
        val cm = connectivity ?: return null
        val vpn = cm.allNetworks.firstOrNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@firstOrNull false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                // ownerUid exists from API 30; before that only one VPN can be up and, while we are Connected, it is ours.
                (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || caps.ownerUid == Process.myUid())
        } ?: return null
        val link = cm.getLinkProperties(vpn) ?: return null
        return TunnelLinkSnapshot(
            routeDestinations = link.routes.map { it.destination.toString() },
            dnsServers = link.dnsServers.mapNotNull { it.hostAddress },
            hasGlobalIpv6Address = link.linkAddresses.any { la ->
                val a = la.address
                a is Inet6Address && !a.isLinkLocalAddress && !a.isLoopbackAddress
            },
        )
    }
}
