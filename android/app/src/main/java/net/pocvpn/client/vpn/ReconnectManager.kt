package net.pocvpn.client.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network

/** Client-side network-loss detection. Actual AWG reconnect across a real gateway remains UNVERIFIED until B8+. */
interface ReconnectManager {
    fun start(onNetworkLost: () -> Unit, onNetworkAvailable: () -> Unit)
    fun stop()
    fun isNetworkAvailable(): Boolean
}

class AndroidReconnectManager(context: Context) : ReconnectManager {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private var callback: ConnectivityManager.NetworkCallback? = null

    @Volatile private var networkAvailable = false

    override fun start(onNetworkLost: () -> Unit, onNetworkAvailable: () -> Unit) {
        stop()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                networkAvailable = true
                onNetworkAvailable()
            }

            override fun onLost(network: Network) {
                networkAvailable = false
                onNetworkLost()
            }
        }
        callback = cb
        connectivityManager.registerDefaultNetworkCallback(cb)
    }

    override fun stop() {
        callback?.let {
            try {
                connectivityManager.unregisterNetworkCallback(it)
            } catch (_: IllegalArgumentException) {
                // already unregistered - not an error for our purposes
            }
        }
        callback = null
    }

    override fun isNetworkAvailable(): Boolean = networkAvailable
}

/** Bounded exponential backoff with jitter. Pure/deterministic when `random` is fixed, for tests. */
object ReconnectBackoff {
    const val BASE_DELAY_MS = 1_000L
    const val MAX_DELAY_MS = 30_000L
    const val MAX_ATTEMPTS = 8

    fun delayForAttempt(attempt: Int, random: () -> Double = Math::random): Long {
        require(attempt >= 1) { "attempt must be >= 1" }
        val shift = (attempt - 1).coerceAtMost(10)
        val exponential = BASE_DELAY_MS * (1L shl shift)
        val capped = exponential.coerceAtMost(MAX_DELAY_MS)
        val jitter = (capped * 0.2 * random()).toLong()
        return capped + jitter
    }
}
