package net.pocvpn.client.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest

/** Client-side network-loss detection. Actual AWG reconnect across a real gateway remains UNVERIFIED until B8+. */
interface ReconnectManager {
    fun start(onNetworkLost: () -> Unit, onNetworkAvailable: () -> Unit)
    fun stop()
    fun isNetworkAvailable(): Boolean
}

/**
 * B30B - tracks whether AT LEAST ONE matching network is currently available,
 * from a stream of per-network onAvailable/onLost events - pulled out as a
 * pure, Android-type-free helper (same "extract the actual logic so it's
 * directly unit-testable" pattern [isFreshHandshake]/[buildNetworkProfile]
 * already use elsewhere in this codebase) so the exact multi-network
 * bookkeeping [AndroidReconnectManager] depends on (a WiFi<->mobile handover
 * where the OLD network is lost but a DIFFERENT one is already/still
 * available must NOT report "no network available") is verifiable without
 * Robolectric or a real ConnectivityManager. [id] is whatever the caller uses
 * to identify one network (a real [android.net.Network] in production, a
 * plain Int in tests).
 */
internal class NetworkAvailabilitySet {
    private val available = mutableSetOf<Any>()

    /** Returns true exactly when this call transitions empty -> non-empty. */
    fun markAvailable(id: Any): Boolean {
        val wasEmpty = available.isEmpty()
        available.add(id)
        return wasEmpty && available.isNotEmpty()
    }

    /** Returns true exactly when this call transitions non-empty -> empty. */
    fun markLost(id: Any): Boolean {
        val wasEmpty = available.isEmpty()
        available.remove(id)
        return !wasEmpty && available.isEmpty()
    }

    fun isEmpty(): Boolean = available.isEmpty()
}

/**
 * B30B review fix (PR #46) - the blocker: [AndroidReconnectManager]'s own
 * `stop()` unregistered the Android callback but never reset ITS SHARED
 * [NetworkAvailabilitySet]/`networkAvailable` fields, so a network id (or a
 * stale "still available" flag) from an OLD start()/stop() lifetime could
 * leak into a NEW one - e.g. stop() while a network was up, then start()
 * again with genuinely nothing available, would still report
 * isNetworkAvailable()==true from the never-cleared old state.
 *
 * Fix: each start() begins a brand-new GENERATION with its own fresh
 * [NetworkAvailabilitySet] and `networkAvailable=false` - the "construct a
 * fresh instance per registration lifetime" design, not a shared-field
 * reset, specifically because it ALSO closes the race a mere reset() could
 * not: an in-flight callback invocation from an OLD registration (already
 * posted before `stop()`'s `unregisterNetworkCallback` takes effect - Android
 * gives no synchronous guarantee against this) is tagged with the OLD
 * generation number at capture time (see [AndroidReconnectManager.start]),
 * so [onAvailable]/[onLost] below reject it outright rather than letting it
 * mutate the NEW generation's state - structurally impossible for a stale
 * callback to corrupt the current one, not merely "unlikely". Pulled out
 * pure/Android-type-free (same reasoning as [NetworkAvailabilitySet] itself)
 * so this exact lifecycle-reset/stale-callback-rejection behavior is
 * directly unit-testable.
 */
internal class ReconnectAvailabilityLifecycle {
    private var currentGeneration = 0L
    private var availability = NetworkAvailabilitySet()

    @Volatile var networkAvailable = false
        private set

    /** Starts a fresh generation - empty availability, networkAvailable=false - and returns its id. */
    fun beginGeneration(): Long {
        currentGeneration++
        availability = NetworkAvailabilitySet()
        networkAvailable = false
        return currentGeneration
    }

    /** Ends whatever generation is current - bumps the generation id (so any still-in-flight callback tagged with it is now stale) and clears networkAvailable. */
    fun endGeneration() {
        currentGeneration++
        networkAvailable = false
    }

    /** Returns true exactly when [generation] is current AND this call transitions empty -> non-empty for it - a stale [generation] is silently ignored. */
    fun onAvailable(generation: Long, id: Any): Boolean {
        if (generation != currentGeneration) return false
        val transitioned = availability.markAvailable(id)
        networkAvailable = true
        return transitioned
    }

    /** Returns true exactly when [generation] is current AND this call transitions non-empty -> empty for it - a stale [generation] is silently ignored. */
    fun onLost(generation: Long, id: Any): Boolean {
        if (generation != currentGeneration) return false
        val lostAll = availability.markLost(id)
        if (lostAll) networkAvailable = false
        return lostAll
    }
}

/**
 * B30B physical-validation fix - root cause: [ConnectivityManager
 * .registerDefaultNetworkCallback] reports changes to THIS APP'S OWN default
 * network, which - once this app's VpnService has established its own tun
 * interface - becomes that VPN network itself, not the real underlying
 * WiFi/cellular network beneath it. Android does not promptly (if ever, for
 * a VpnService that never called `setUnderlyingNetworks`) tear down an
 * app's own already-established VPN network merely because the physical
 * transport under it vanished, so `onLost` for the default network callback
 * essentially never fired on a real Oppo CPH2173 in a confirmed, total,
 * ~70s connectivity outage (airplane mode + WiFi disabled, zero
 * NetworkAgentInfo) - `_state` stayed "Connected"/Protected the whole time
 * for the TLS_TCP session because [VpnController.handleNetworkLost] was
 * simply never invoked, not because of anything transport-specific.
 *
 * AWG's OWN failure detection ([VpnController.awaitFreshHandshake]/the
 * AmneziaWG Go backend's own UDP send failures) is entirely independent of
 * this class and was never affected - that path degrades correctly even
 * with this bug present, which is why only Xray/TLS_TCP (and, latently,
 * XRAY_REALITY - see [VpnController.handleNetworkLost]'s updated docs)
 * exhibited stale-Protected.
 *
 * Fix: request [NetworkCapabilities.NET_CAPABILITY_NOT_VPN] explicitly, via
 * [ConnectivityManager.registerNetworkCallback] (not
 * `registerDefaultNetworkCallback`) - the documented Android pattern for a
 * VPN-owning app to observe its REAL underlying connectivity rather than its
 * own resulting default network. Because a matching request can report
 * MULTIPLE concurrently-available networks (e.g. WiFi AND cellular both up),
 * [NetworkAvailabilitySet] tracks the whole set so [onNetworkLost] fires
 * ONLY when it becomes genuinely empty - a WiFi<->cellular handover where a
 * usable network is available throughout never spuriously reports "network
 * lost" (Phase C's own "normal handover should not cause unnecessary
 * permanent failure" requirement), while a real total loss still reports
 * correctly. No change to [ReconnectManager]'s contract, [VpnController],
 * or anything downstream of `onNetworkLost`/`onNetworkAvailable` - this is
 * strictly a same-interface fix to what evidence feeds the EXISTING
 * `handleNetworkLost()`/`reconnectLoop()` health authority, never a second
 * one.
 */
class AndroidReconnectManager(context: Context) : ReconnectManager {
    private val connectivityManager =
        context.applicationContext.getSystemService(ConnectivityManager::class.java)
    private var callback: ConnectivityManager.NetworkCallback? = null
    private val lifecycle = ReconnectAvailabilityLifecycle()

    override fun start(onNetworkLost: () -> Unit, onNetworkAvailable: () -> Unit) {
        stop()
        // B30B review fix (PR #46) - this generation id is captured HERE, in
        // this specific start() call's own local val, then closed over by
        // the callback below - a callback instance from a PREVIOUS start()
        // carries the PREVIOUS (now-stale) generation baked into ITS OWN
        // closure, so it can never be confused with this one even if it
        // fires late (see ReconnectAvailabilityLifecycle's own docs).
        val generation = lifecycle.beginGeneration()
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (lifecycle.onAvailable(generation, network)) onNetworkAvailable()
            }

            override fun onLost(network: Network) {
                if (lifecycle.onLost(generation, network)) onNetworkLost()
            }
        }
        callback = cb
        connectivityManager.registerNetworkCallback(request, cb)
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
        lifecycle.endGeneration()
    }

    override fun isNetworkAvailable(): Boolean = lifecycle.networkAvailable
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
