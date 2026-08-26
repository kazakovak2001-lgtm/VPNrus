package net.pocvpn.client.vpn

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import net.pocvpn.client.vpn.config.TransportConfig

/**
 * Abstraction for a VPN data-plane implementation. Additional transports
 * (fallback, TLS-based, etc.) are added by implementing this interface -
 * no other layer depends on a specific tunnel technology, and AWG-specific
 * fields never appear outside AmneziaWgTransport / its config mapper.
 */
interface VpnTransport {
    val name: String

    /** Null if no OS-level permission is needed or it's already granted; otherwise the Intent to launch. */
    fun preparePermissionIntent(): Intent?

    suspend fun connect(config: TransportConfig)
    suspend fun disconnect()
    fun observeState(): Flow<TransportState>
}
