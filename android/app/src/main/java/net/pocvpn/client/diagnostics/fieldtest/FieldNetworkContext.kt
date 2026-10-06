package net.pocvpn.client.diagnostics.fieldtest

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.TelephonyManager
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address

/**
 * Field-test network context: what network the observation was made on.
 * Permission-free reads only (ACCESS_NETWORK_STATE is already declared;
 * no READ_PHONE_STATE, no location). Deliberately NOT recorded: the
 * device's own public IP, phone number, IMSI/IMEI, SSID, the local
 * addresses themselves and the ISP resolver addresses - only their
 * presence/count. Operator name and MCC/MNC identify the network, not the
 * subscriber, and are what a restricted-network observation needs (B54).
 */
object FieldNetworkContext {

    fun collect(context: Context): JSONObject {
        val obj = JSONObject()
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val tm = context.getSystemService(TelephonyManager::class.java)
        val active = cm?.activeNetwork
        obj.put("telephony", telephony(tm))
        obj.put("activeNetwork", active?.let { describeNetwork(cm, it) } ?: JSONObject.NULL)
        val all = JSONArray()
        cm?.allNetworks?.forEach { network -> all.put(describeNetwork(cm, network)) }
        obj.put("allNetworks", all)
        obj.put("vpnNetworkPresent", vpnNetwork(cm) != null)
        obj.put("summary", summary(obj))
        return obj
    }

    /** The network carrying our own VPN tunnel, or null when no VPN network exists. */
    fun vpnNetwork(context: Context): Network? = vpnNetwork(context.getSystemService(ConnectivityManager::class.java))

    private fun vpnNetwork(cm: ConnectivityManager?): Network? =
        cm?.allNetworks?.firstOrNull { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true }

    fun device(): JSONObject = JSONObject()
        .put("manufacturer", Build.MANUFACTURER)
        .put("model", Build.MODEL)
        .put("androidRelease", Build.VERSION.RELEASE)
        .put("sdkInt", Build.VERSION.SDK_INT)
        .put("supportedAbis", JSONArray(Build.SUPPORTED_ABIS.toList()))

    private fun telephony(tm: TelephonyManager?): JSONObject {
        val obj = JSONObject()
        if (tm == null) return obj.put("available", false)
        obj.put("available", true)
        obj.put("phoneType", tm.phoneType)
        safe { obj.put("simState", tm.simState) }
        safe { obj.put("networkOperatorName", tm.networkOperatorName.orEmpty()) }
        // MCC+MNC of the registered network (e.g. 25001 = MTS RU) - identifies the operator, not the subscriber.
        safe { obj.put("networkOperatorMccMnc", tm.networkOperator.orEmpty()) }
        safe { obj.put("networkCountryIso", tm.networkCountryIso.orEmpty()) }
        safe { obj.put("simOperatorName", tm.simOperatorName.orEmpty()) }
        safe { obj.put("simOperatorMccMnc", tm.simOperator.orEmpty()) }
        safe { obj.put("simCountryIso", tm.simCountryIso.orEmpty()) }
        safe { obj.put("isNetworkRoaming", tm.isNetworkRoaming) }
        return obj
    }

    private fun describeNetwork(cm: ConnectivityManager, network: Network): JSONObject {
        val obj = JSONObject()
        val caps = cm.getNetworkCapabilities(network)
        val link = cm.getLinkProperties(network)
        if (caps != null) {
            val transports = JSONArray()
            TRANSPORTS.forEach { (id, name) -> if (caps.hasTransport(id)) transports.put(name) }
            obj.put("transports", transports)
            obj.put("internet", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
            obj.put("validated", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            obj.put("captivePortal", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL))
            obj.put("notMetered", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
            obj.put("notRoaming", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING))
            obj.put("notVpn", caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN))
            obj.put("downstreamKbps", caps.linkDownstreamBandwidthKbps)
            obj.put("upstreamKbps", caps.linkUpstreamBandwidthKbps)
        }
        if (link != null) {
            obj.put("interfaceName", link.interfaceName ?: JSONObject.NULL)
            val addresses = link.linkAddresses.map { it.address }
            obj.put("hasIpv4", addresses.any { it is Inet4Address })
            obj.put("hasGlobalIpv6", addresses.any { it is Inet6Address && !it.isLinkLocalAddress && !it.isSiteLocalAddress })
            obj.put("dnsServerCount", link.dnsServers.size)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                obj.put("privateDnsActive", link.isPrivateDnsActive)
                obj.put("privateDnsServerName", link.privateDnsServerName ?: JSONObject.NULL)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) obj.put("mtu", link.mtu)
            obj.put("hasDefaultRoute", link.routes.any { it.isDefaultRoute })
        }
        return obj
    }

    private fun summary(obj: JSONObject): String {
        val t = obj.optJSONObject("telephony")
        val a = obj.optJSONObject("activeNetwork")
        val transports = a?.optJSONArray("transports")?.let { arr -> (0 until arr.length()).joinToString("+") { arr.getString(it) } } ?: "none"
        val operator = t?.optString("networkOperatorName").orEmpty().ifBlank { "-" }
        val mccMnc = t?.optString("networkOperatorMccMnc").orEmpty().ifBlank { "-" }
        val country = t?.optString("networkCountryIso").orEmpty().ifBlank { "-" }
        val roaming = t?.optBoolean("isNetworkRoaming") == true
        val validated = a?.optBoolean("validated") == true
        return "$transports, operator $operator ($mccMnc, $country)${if (roaming) ", ROAMING" else ""}, validated=$validated, ipv6=${a?.optBoolean("hasGlobalIpv6")}, privateDns=${a?.optBoolean("privateDnsActive")}"
    }

    private inline fun safe(block: () -> Unit) {
        try { block() } catch (_: SecurityException) {} catch (_: RuntimeException) {}
    }

    private val TRANSPORTS = listOf(
        NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
        NetworkCapabilities.TRANSPORT_WIFI to "WIFI",
        NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET",
        NetworkCapabilities.TRANSPORT_VPN to "VPN",
        NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH",
    )
}
