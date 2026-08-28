package net.pocvpn.client.diagnostics

import net.pocvpn.client.vpn.TransportState

/**
 * Everything shown on the developer diagnostics screen. Every field here is
 * intentionally non-secret - this type must never gain a field derived from
 * a private key or a full AWG config string.
 */
data class DiagnosticsSnapshot(
    val transportState: TransportState = TransportState.Disconnected,
    val permissionGranted: Boolean = false,
    val gatewayConfigured: Boolean = false,
    val endpointDisplay: String = "NOT CONFIGURED",
    val transportType: String = "AWG 3.1",
    val reconnectAttempts: Int = 0,
    val lastError: VpnError? = null,
    val networkType: String = "unknown",
    // B8B3D - from VpnTransport.stats() (AmneziaWgTransport.stats(), backed
    // by Backend.getLastHandshake/getStatistics - see that class's own
    // docs). Non-secret: byte counters and a handshake timestamp, nothing
    // key-derived.
    val lastHandshakeEpochMillis: Long? = null,
    val bytesReceived: Long? = null,
    val bytesSent: Long? = null,
)
