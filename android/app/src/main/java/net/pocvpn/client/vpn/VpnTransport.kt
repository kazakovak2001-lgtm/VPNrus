package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import net.pocvpn.client.smartconnect.TrafficProgressSnapshot
import net.pocvpn.client.transport.ProbeContext
import net.pocvpn.client.transport.ProbeResult
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * Abstraction for a VPN data-plane implementation. Additional transports
 * (fallback, TLS-based, etc.) are added by implementing this interface -
 * no other layer depends on a specific tunnel technology, and AWG-specific
 * fields never appear outside AmneziaWgTransport / its config mapper.
 *
 * [probe]/[stats] default to explicit Unsupported results - a transport only
 * overrides them once it can answer truthfully (see TransportStats/ProbeResult).
 */
interface VpnTransport {
    val name: String
    val kind: TransportKind
    val capabilities: TransportCapabilities
    val underlyingNetworkRecovery: UnderlyingNetworkRecovery
        get() = UnderlyingNetworkRecovery.IN_PLACE

    /** Null if no OS-level permission is needed or it's already granted; otherwise the Intent to launch. */
    fun preparePermissionIntent(): Intent?

    suspend fun connect(config: TransportConfig)
    suspend fun disconnect()
    fun observeState(): Flow<TransportState>

    suspend fun probe(context: ProbeContext): ProbeResult = ProbeResult.Unsupported
    suspend fun stats(): TransportStats = TransportStats.Unsupported

    /**
     * B-WL-R3 - post-connect traffic-progress verdicts for the CURRENT
     * session, produced by the transport's own existing health loop (for
     * Xray: the B33 session watchdog in XrayCoreController). Empty by
     * default: a transport that has no progress signal emits nothing, which
     * VpnController treats as "no progress claim", never as unhealthy.
     * Deliberately separate from [stats]: [TransportStats.Counters] also
     * carries AWG handshake-freshness semantics that VpnController's
     * connect/reconnect gates rely on, which a TCP/Xray byte counter must
     * never be mistaken for.
     */
    fun observeTrafficProgress(): Flow<TrafficProgressSnapshot> = emptyFlow()
}

enum class UnderlyingNetworkRecovery {
    IN_PLACE,
    RESTART_SESSION,
}
