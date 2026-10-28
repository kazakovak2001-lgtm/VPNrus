package net.pocvpn.client.diagnostics.fieldtest

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import org.json.JSONArray
import org.json.JSONObject

/**
 * Field-test network event timeline: Android's own connectivity callbacks
 * (onAvailable / onLost / onCapabilitiesChanged / onLinkPropertiesChanged)
 * with a shared time base, so a failed attempt can be correlated with a
 * change or loss of the underlying network. Observation only: it never
 * requests, changes or binds a network.
 *
 * Privacy: only the opaque network id, transport names, capability flags,
 * the interface name and the DNS-server COUNT are kept - never addresses,
 * SSIDs or identifiers. Missing values are null ("not available"), never 0.
 */
enum class NetworkEventType { AVAILABLE, LOST, CAPABILITIES_CHANGED, LINK_CHANGED }

data class NetworkEvent(
    val tUtcMillis: Long,
    /** Milliseconds since the log began (the test start). */
    val tRelMs: Long,
    val type: NetworkEventType,
    val networkId: String,
    val transports: List<String>,
    val validated: Boolean?,
    val hasInternet: Boolean?,
    val hasDefaultRoute: Boolean?,
    val interfaceName: String?,
    val dnsServerCount: Int?,
    /**
     * Android replays the CURRENT state of every network right after a callback is
     * registered; such events describe the starting situation, not a change.
     */
    val initial: Boolean = false,
) {
    /** True for the network carrying our own tunnel. */
    val isVpn: Boolean get() = "VPN" in transports

    fun toJson(): JSONObject = JSONObject()
        .put("tUtcMillis", tUtcMillis)
        .put("tRelMs", tRelMs)
        .put("type", type.name)
        .put("networkId", networkId)
        .put("transports", JSONArray(transports))
        .put("validated", validated ?: JSONObject.NULL)
        .put("hasInternet", hasInternet ?: JSONObject.NULL)
        .put("hasDefaultRoute", hasDefaultRoute ?: JSONObject.NULL)
        .put("interfaceName", interfaceName ?: JSONObject.NULL)
        .put("dnsServerCount", dnsServerCount ?: JSONObject.NULL)
        .put("initial", initial)
}

data class NetworkEventSnapshot(
    val events: List<NetworkEvent>,
    /** Events discarded because the log was full (the oldest are kept). */
    val dropped: Int,
    /** Repeated capability/link callbacks identical to the previous one for the same network, not stored. */
    val suppressedRepeats: Int,
    /** Non-null when the callback could not be registered: the timeline is then empty, not "no changes". */
    val registrationError: String?,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("events", JSONArray().apply { events.forEach { put(it.toJson()) } })
        .put("dropped", dropped)
        .put("suppressedRepeats", suppressedRepeats)
        .put("registrationError", registrationError ?: JSONObject.NULL)
}

/** Events that fall in one attempt's time window, reduced to what a diagnosis needs. */
data class NetworkWindow(
    val underlyingLost: Int,
    val unvalidatedSeen: Boolean,
    val changes: Int,
)

/** Bounded, thread-safe event buffer with an injectable clock (pure and JVM-testable). */
class NetworkEventLog(
    private val clock: () -> Long,
    private val capacity: Int = 300,
) {
    private val events = ArrayList<NetworkEvent>()
    private var startedAt = clock()
    private var dropped = 0
    private var suppressed = 0
    private val lastByKey = HashMap<String, List<Any?>>()
    private var registrationError: String? = null

    @Synchronized fun begin() {
        events.clear()
        dropped = 0
        suppressed = 0
        lastByKey.clear()
        registrationError = null
        startedAt = clock()
    }

    @Synchronized fun failRegistration(reason: String) {
        registrationError = reason
    }

    @Synchronized fun record(
        type: NetworkEventType,
        networkId: String,
        transports: List<String>,
        validated: Boolean?,
        hasInternet: Boolean?,
        hasDefaultRoute: Boolean?,
        interfaceName: String?,
        dnsServerCount: Int?,
    ) {
        // Wi-Fi reports a capability change every ~2 s (bandwidth estimate, signal); identical repeats
        // would fill the buffer within minutes and hide the end of a long monitor run.
        val state = listOf(transports, validated, hasInternet, hasDefaultRoute, interfaceName, dnsServerCount)
        if (type == NetworkEventType.CAPABILITIES_CHANGED || type == NetworkEventType.LINK_CHANGED) {
            val key = "$networkId/${type.name}"
            if (lastByKey[key] == state) {
                suppressed++
                return
            }
            lastByKey[key] = state
        }
        if (events.size >= capacity) {
            dropped++
            return
        }
        val now = clock()
        val relative = now - startedAt
        events += NetworkEvent(now, relative, type, networkId, transports, validated, hasInternet, hasDefaultRoute, interfaceName, dnsServerCount, initial = relative < INITIAL_SNAPSHOT_MS)
    }

    @Synchronized fun snapshot(): NetworkEventSnapshot = NetworkEventSnapshot(events.toList(), dropped, suppressed, registrationError)

    private companion object {
        const val INITIAL_SNAPSHOT_MS = 500L
    }
}

/** Reduces [events] inside [fromUtc, toUtc) to a [NetworkWindow]. VPN networks are ignored: they are our own tunnel. */
fun networkWindow(events: List<NetworkEvent>, fromUtc: Long, toUtc: Long): NetworkWindow {
    val inWindow = events.filter { it.tUtcMillis in fromUtc until toUtc && !it.isVpn }
    return NetworkWindow(
        underlyingLost = inWindow.count { it.type == NetworkEventType.LOST },
        unvalidatedSeen = inWindow.any { it.validated == false },
        changes = inWindow.size,
    )
}

/** Android adapter feeding a [NetworkEventLog]; the only Android-dependent part. */
class AndroidNetworkEventSource(context: Context, private val log: NetworkEventLog) {
    private val cm = context.getSystemService(ConnectivityManager::class.java)
    private var callback: ConnectivityManager.NetworkCallback? = null

    fun start() {
        log.begin()
        val manager = cm
        if (manager == null) {
            log.failRegistration("ConnectivityManager unavailable")
            return
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            // Also see our own VPN network, so its life cycle is on the same timeline.
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = emit(NetworkEventType.AVAILABLE, network, null, null)
            override fun onLost(network: Network) = emit(NetworkEventType.LOST, network, null, null)
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                emit(NetworkEventType.CAPABILITIES_CHANGED, network, caps, null)
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) =
                emit(NetworkEventType.LINK_CHANGED, network, null, lp)
        }
        try {
            manager.registerNetworkCallback(request, cb)
            callback = cb
        } catch (e: SecurityException) {
            log.failRegistration("SecurityException")
        } catch (e: RuntimeException) {
            log.failRegistration(e.javaClass.simpleName)
        }
    }

    fun stop(): NetworkEventSnapshot {
        callback?.let { cb ->
            try {
                cm?.unregisterNetworkCallback(cb)
            } catch (_: RuntimeException) {
            }
        }
        callback = null
        return log.snapshot()
    }

    private fun emit(type: NetworkEventType, network: Network, capsIn: NetworkCapabilities?, linkIn: LinkProperties?) {
        val manager = cm
        val caps = capsIn ?: manager?.getNetworkCapabilities(network)
        val link = linkIn ?: manager?.getLinkProperties(network)
        val transports = TRANSPORTS.filter { caps?.hasTransport(it.first) == true }.map { it.second }
        log.record(
            type = type,
            networkId = network.toString(),
            transports = transports,
            validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            hasInternet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            hasDefaultRoute = link?.routes?.any { it.isDefaultRoute },
            interfaceName = link?.interfaceName,
            dnsServerCount = link?.dnsServers?.size,
        )
    }

    private companion object {
        val TRANSPORTS = listOf(
            NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
            NetworkCapabilities.TRANSPORT_WIFI to "WIFI",
            NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET",
            NetworkCapabilities.TRANSPORT_VPN to "VPN",
            NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH",
        )
    }
}
