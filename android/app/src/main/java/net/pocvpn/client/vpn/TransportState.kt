package net.pocvpn.client.vpn

/** Observable state of a VpnTransport. Transport-agnostic - no AWG-specific detail here. */
sealed class TransportState {
    object Disconnected : TransportState()
    object Connecting : TransportState()
    object Connected : TransportState()
    object Disconnecting : TransportState()
    data class Reconnecting(val attempt: Int) : TransportState()
    data class Error(val message: String, val cause: Throwable? = null) : TransportState()
}
