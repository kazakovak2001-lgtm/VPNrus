package net.pocvpn.client.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Observes the current default network via real ConnectivityManager
 * callbacks (no polling) and exposes a truthful NetworkProfile. Mirrors
 * AndroidReconnectManager's registration/lifecycle pattern for consistency:
 * start() is idempotent (stops any previous registration first), stop()
 * unregisters and clears all held state so nothing leaks across restarts.
 */
class NetworkProfiler(context: Context) {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)

    private val generationCounter = AtomicLong(0)
    private val _profile = MutableStateFlow(NetworkProfile.unavailable(0))
    val profile: StateFlow<NetworkProfile> = _profile.asStateFlow()

    private var callback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentCapabilities: NetworkCapabilities? = null
    @Volatile private var currentLinkProperties: LinkProperties? = null

    fun start() {
        stop()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                currentCapabilities = capabilities
                emit()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                currentLinkProperties = linkProperties
                emit()
            }

            override fun onLost(network: Network) {
                currentCapabilities = null
                currentLinkProperties = null
                _profile.value = NetworkProfile.unavailable(generationCounter.incrementAndGet())
            }
        }
        callback = cb
        connectivityManager.registerDefaultNetworkCallback(cb)
    }

    fun stop() {
        callback?.let {
            try {
                connectivityManager.unregisterNetworkCallback(it)
            } catch (_: IllegalArgumentException) {
                // already unregistered - not an error for our purposes
            }
        }
        callback = null
        currentCapabilities = null
        currentLinkProperties = null
    }

    private fun emit() {
        val capabilities = currentCapabilities ?: return
        val linkAddresses = currentLinkProperties?.linkAddresses.orEmpty()
        val signals = RawNetworkSignals(
            hasWifi = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
            hasCellular = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR),
            hasEthernet = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET),
            validatedInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            notMetered = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            notRoaming = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
            captivePortal = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            hasIpv4Address = linkAddresses.any { it.address is Inet4Address },
            hasIpv6Address = linkAddresses.any { it.address is Inet6Address },
            isVpnTransport = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            dnsServerAddresses = currentLinkProperties?.dnsServers.orEmpty().map { it.hostAddress ?: "" }.filter { it.isNotEmpty() },
        )
        _profile.value = buildNetworkProfile(signals, generationCounter.incrementAndGet())
    }
}

/**
 * B8I - the raw booleans a real NetworkCapabilities/LinkProperties pair
 * exposes, already extracted - no android.net.* type appears here, so this
 * (and buildNetworkProfile below) stays directly unit-testable on the plain
 * JVM without Robolectric/mocking, same pattern as isFreshHandshake/
 * resolveAppRoutingLists elsewhere in this codebase. NetworkProfiler.emit()
 * is the ONLY place that constructs one from real Android objects.
 */
internal data class RawNetworkSignals(
    val hasWifi: Boolean,
    val hasCellular: Boolean,
    val hasEthernet: Boolean,
    val validatedInternet: Boolean,
    val notMetered: Boolean,
    val notRoaming: Boolean,
    val captivePortal: Boolean,
    val hasIpv4Address: Boolean,
    val hasIpv6Address: Boolean,
    val isVpnTransport: Boolean,
    val dnsServerAddresses: List<String> = emptyList(),
)

internal fun buildNetworkProfile(signals: RawNetworkSignals, generation: Long): NetworkProfile {
    val type = when {
        signals.hasWifi -> NetworkType.WIFI
        signals.hasCellular -> NetworkType.CELLULAR
        signals.hasEthernet -> NetworkType.ETHERNET
        else -> NetworkType.OTHER
    }
    return NetworkProfile(
        type = type,
        validatedInternet = signals.validatedInternet,
        metered = !signals.notMetered,
        roaming = !signals.notRoaming,
        captivePortal = signals.captivePortal,
        ipv4Available = signals.hasIpv4Address,
        ipv6Available = signals.hasIpv6Address,
        vpnActive = signals.isVpnTransport,
        generation = generation,
        dnsServerAddresses = signals.dnsServerAddresses,
    )
}
