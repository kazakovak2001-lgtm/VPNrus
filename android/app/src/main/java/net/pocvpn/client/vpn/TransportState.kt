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

/**
 * B13 consolidated review fix (finding 5) - true while a VPN session
 * genuinely exists in a state where a gateway switch would misrepresent
 * WHERE traffic is actually exiting: Connecting/Reconnecting (an attempt is
 * in flight, possibly still on the previous gateway), Connected (traffic IS
 * exiting the currently active gateway right now), and Disconnecting (the
 * previous session has not yet fully torn down). Deliberately EXCLUDES
 * Disconnected (no session, nothing to misrepresent) and Error/
 * HandshakeFailed (the attempt already failed/settled - no traffic is
 * exiting anywhere on this gateway, so a fresh selection before retrying is
 * truthful, not misleading).
 *
 * THE one shared predicate for this rule - MainViewModel.selectGateway()
 * and AppRoot's own gateway-picker-open gating both defer to this SAME
 * function (see each call site's own docs), never two independently
 * maintained copies of the same four-state list.
 */
fun TransportState.blocksGatewaySelection(): Boolean = when (this) {
    is TransportState.Connecting, is TransportState.Connected,
    is TransportState.Reconnecting, is TransportState.Disconnecting -> true
    is TransportState.Disconnected, is TransportState.Error, is TransportState.HandshakeFailed -> false
}
