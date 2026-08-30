package net.pocvpn.client.network

/**
 * A future reachability/restrictiveness signal Smart Connect could one day
 * use (UDP/QUIC/TCP-443 reachability, a restrictive-network score). No probe
 * for any of these exists yet - every NetworkProfile carries [Unknown] here
 * until a real, verified probe is added. Never infer "censorship"/"DPI" from
 * weak signals - see NetworkProfiler.
 */
sealed class ProbeSignal {
    object Unknown : ProbeSignal()
}

/**
 * Transport-independent, truthfully-observable-today facts about the
 * current network. Nothing here is protocol-specific and nothing is
 * inferred beyond what Android's ConnectivityManager actually reports.
 *
 * [generation] is a monotonically increasing sequence number NetworkProfiler
 * assigns to each distinct observation, so consumers (Smart Connect, tests)
 * can tell "a new network event happened" apart from a re-emitted value.
 */
data class NetworkProfile(
    val type: NetworkType,
    val validatedInternet: Boolean,
    val metered: Boolean,
    val roaming: Boolean?,
    val captivePortal: Boolean?,
    val ipv4Available: Boolean,
    val ipv6Available: Boolean,
    val vpnActive: Boolean?,
    val generation: Long,
    val udpReachability: ProbeSignal = ProbeSignal.Unknown,
    val quicReachability: ProbeSignal = ProbeSignal.Unknown,
    val tcp443Reachability: ProbeSignal = ProbeSignal.Unknown,
    val restrictiveNetworkScore: ProbeSignal = ProbeSignal.Unknown,
    /**
     * B11 - resolver IP addresses from the current LinkProperties, already
     * exposed to this app for routing purposes. Coarse-only input for
     * NetworkFingerprinter's local network memory - never a destination,
     * query, or anything traffic-related. Defaults to empty so every
     * pre-B11 call site/test is unaffected.
     */
    val dnsServerAddresses: List<String> = emptyList(),
) {
    val isUsable: Boolean get() = type != NetworkType.NONE && validatedInternet

    companion object {
        /** The truthful starting/no-network state - never a stale "connected" guess. */
        fun unavailable(generation: Long): NetworkProfile = NetworkProfile(
            type = NetworkType.NONE,
            validatedInternet = false,
            metered = false,
            roaming = null,
            captivePortal = null,
            ipv4Available = false,
            ipv6Available = false,
            vpnActive = null,
            generation = generation,
        )
    }
}
