package net.pocvpn.client.fieldtest

import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * The field-test connect flow's own state machine - deliberately separate
 * from [net.pocvpn.client.vpn.TransportState]/[net.pocvpn.client.vpn.VpnController]
 * and from [net.pocvpn.client.bootstrap.BootstrapState] (same reasoning as
 * that file's own docs: this is a small, standalone flow with no activation/
 * Smart Connect machinery behind it - entangling it into either existing
 * state machine would be risk, not reuse). [FieldTestTunnelController] is
 * this state machine's ONE owner.
 *
 * ```
 * Idle -> Connecting(GERMANY) -> Protected(GERMANY)
 *              |
 *              v (Frankfurt: no usable handshake, or handshake ok but health check fails)
 *         Connecting(STOCKHOLM) -> Protected(STOCKHOLM)
 *              |
 *              v (Stockholm also fails)
 *         Failed(attempted = [GERMANY, STOCKHOLM])
 * ```
 */
sealed class FieldTestState {
    object Idle : FieldTestState()
    data class Connecting(val candidate: ProductionGatewayId) : FieldTestState()
    data class Protected(val candidate: ProductionGatewayId) : FieldTestState()

    /** Every known candidate was tried and none produced a usable, health-verified data plane. */
    data class Failed(val attempted: List<ProductionGatewayId>) : FieldTestState()
}
