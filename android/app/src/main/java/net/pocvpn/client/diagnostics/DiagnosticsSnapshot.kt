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
)
