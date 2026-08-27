package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.flow.Flow
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

    /** Null if no OS-level permission is needed or it's already granted; otherwise the Intent to launch. */
    fun preparePermissionIntent(): Intent?

    suspend fun connect(config: TransportConfig)
    suspend fun disconnect()
    fun observeState(): Flow<TransportState>

    suspend fun probe(context: ProbeContext): ProbeResult = ProbeResult.Unsupported
    suspend fun stats(): TransportStats = TransportStats.Unsupported
}
