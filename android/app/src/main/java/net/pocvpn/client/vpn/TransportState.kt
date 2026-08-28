package net.pocvpn.client.vpn

/** Observable state of a VpnTransport. Transport-agnostic - no AWG-specific detail here. */
sealed class TransportState {
    object Disconnected : TransportState()
    object Connecting : TransportState()
    object Connected : TransportState()
    object Disconnecting : TransportState()
    data class Reconnecting(val attempt: Int) : TransportState()
    data class Error(val message: String, val cause: Throwable? = null) : TransportState()

    /**
     * B8B3D - the transport/VpnService started (interface up, possibly TX>0)
     * but no real AWG handshake was observed for the CURRENT connection
     * attempt within the bounded startup window. Deliberately distinct from
     * [Error] so the UI can show a specific "no VPN handshake" message
     * rather than a generic failure - see VpnController.awaitFirstHandshake.
     */
    object HandshakeFailed : TransportState()
}
