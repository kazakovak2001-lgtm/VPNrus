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
        val type = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            else -> NetworkType.OTHER
        }
        val linkAddresses = currentLinkProperties?.linkAddresses.orEmpty()
        _profile.value = NetworkProfile(
            type = type,
            validatedInternet = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
            roaming = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
            captivePortal = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL),
            ipv4Available = linkAddresses.any { it.address is Inet4Address },
            ipv6Available = linkAddresses.any { it.address is Inet6Address },
            vpnActive = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
            generation = generationCounter.incrementAndGet(),
        )
    }
}
