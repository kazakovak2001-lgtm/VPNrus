package net.pocvpn.client.diagnostics

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import net.pocvpn.client.vpn.TransportState

/** Holds the current non-secret diagnostics snapshot. See DiagnosticsSnapshot for the secrecy invariant. */
class DiagnosticsStore {
    private val _snapshot = MutableStateFlow(DiagnosticsSnapshot())
    val snapshot: StateFlow<DiagnosticsSnapshot> = _snapshot.asStateFlow()

    fun updateTransportState(state: TransportState) {
        _snapshot.value = _snapshot.value.copy(transportState = state)
    }

    fun updatePermission(granted: Boolean) {
        _snapshot.value = _snapshot.value.copy(permissionGranted = granted)
    }

    fun updateGateway(configured: Boolean, endpointDisplay: String) {
        _snapshot.value = _snapshot.value.copy(gatewayConfigured = configured, endpointDisplay = endpointDisplay)
    }

    fun updateReconnectAttempts(attempts: Int) {
        _snapshot.value = _snapshot.value.copy(reconnectAttempts = attempts)
    }

    fun updateNetworkType(type: String) {
        _snapshot.value = _snapshot.value.copy(networkType = type)
    }

    fun recordError(error: VpnError) {
        _snapshot.value = _snapshot.value.copy(lastError = error)
    }

    fun clearError() {
        _snapshot.value = _snapshot.value.copy(lastError = null)
    }
}
