package net.pocvpn.client.bootstrap

import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B36 - the bootstrap-tunnel lifecycle state (task requirement 1):
 *
 * ```
 * Idle -> Connecting(candidate) -> Connected(candidate) -> TearingDown(candidate) -> Idle
 *                 |
 *                 v (candidate exhausted without a usable handshake)
 *            Connecting(nextCandidate) -> ...
 *                 |
 *                 v (every known candidate exhausted)
 *            Unavailable(attempted)
 * ```
 *
 * Deliberately a SEPARATE state machine from [net.pocvpn.client.vpn.TransportState]/
 * [net.pocvpn.client.vpn.VpnController] (task requirement 8's own "avoid a
 * second competing VpnController state machine... unless the existing one
 * cannot own this safely" - see docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md
 * for why VpnController genuinely cannot own this: it is only ever reachable
 * from the Home screen, which requires a provisioned profile to exist at
 * all - see [net.pocvpn.client.ui.screenFor] - so entangling bootstrap into
 * its AutoGatewaySelector/PathScorer/GatewayConfigSnapshot machinery would
 * be pure risk for a state this small, not real reuse). [BootstrapTunnelController]
 * is this state machine's ONE owner.
 */
sealed class BootstrapState {
    object Idle : BootstrapState()
    data class Connecting(val candidate: ProductionGatewayId) : BootstrapState()
    data class Connected(val candidate: ProductionGatewayId) : BootstrapState()
    data class TearingDown(val candidate: ProductionGatewayId) : BootstrapState()

    /** Every known candidate was tried and none produced a usable (fresh-handshake) tunnel. */
    data class Unavailable(val attempted: List<ProductionGatewayId>) : BootstrapState()
}
