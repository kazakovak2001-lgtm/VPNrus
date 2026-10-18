package net.pocvpn.client.vpn

import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.VpnAttemptContext
import net.pocvpn.client.transport.TransportKind

/**
 * B25 (task B) - the real, typed readiness/session-health authority that
 * replaces the generic "TransportState.Connected -> Protected" assumption
 * for a relayed attempt, without touching Direct's own behavior at all.
 *
 * [VpnController.sessionHealth] is the ONE place this is computed (via the
 * pure [computeSessionHealth] below) - UI code must read it instead of
 * re-deriving "Protected" from a raw [TransportState] once a session may be
 * relayed (see [net.pocvpn.client.ui.ProductFlowPresentation.toHomeStatusText]'s
 * own B25 update, which now dispatches on this type).
 *
 * [DirectProtected] is reached under EXACTLY the same condition
 * [TransportState.Connected] always meant for a Direct attempt - a real
 * AWG handshake or an Xray runtime confirmation (see VpnController's own
 * `doConnectAttempt` docs) - byte-for-byte unchanged. [RelayProtected] is
 * reachable ONLY when the relay's own [RelayReadinessStage] has reached
 * [RelayReadinessStage.END_TO_END_DATA_PLANE_OK] - a real end-to-end proof
 * (see [net.pocvpn.client.relay.RelayEndToEndProbe]), never merely
 * [TransportState.Connected] for the ingress hop alone. Every earlier relay
 * stage renders as [RelayHandshake], which is deliberately NOT Protected -
 * task requirement B's own "no intermediate stage may display Protected".
 */
sealed class VpnSessionHealth {
    object Idle : VpnSessionHealth()
    object InProgress : VpnSessionHealth()
    object Reconnecting : VpnSessionHealth()
    object DirectProtected : VpnSessionHealth()

    /**
     * H2-GATE - a Direct session whose transport requires data-plane proof
     * (Hysteria2 only, see [requiresDataPlaneProof]) is Connected but has no
     * fresh, session-scoped B-WL7 VERIFIED yet. Deliberately NOT Protected.
     */
    object DataPlaneVerifying : VpnSessionHealth()
    data class RelayHandshake(val stage: RelayReadinessStage) : VpnSessionHealth()
    object RelayProtected : VpnSessionHealth()
    data class Failed(val message: String) : VpnSessionHealth()
}

/**
 * Pure function, deliberately file-scope (not a [VpnController] member) so
 * it is directly unit-testable with concrete [TransportState]/
 * [VpnAttemptContext]/[RelayReadinessStage] values, independent of any
 * transport double or coroutine machinery - the same reasoning
 * [isFreshHandshake] in VpnController.kt already follows.
 *
 * [relayStage] is ignored entirely for [VpnAttemptContext.Direct] - a
 * Direct attempt's health can never be influenced by a stray relay-stage
 * value left over from a prior relayed attempt (see [VpnController]'s own
 * reset discipline in `connect()`/`disconnect()`).
 *
 * [dataPlaneProofPending] (H2-GATE) holds a Direct Connected session at
 * [VpnSessionHealth.DataPlaneVerifying]; VpnController sets it only for a
 * kind in [requiresDataPlaneProof], so every other transport is unchanged.
 */
fun computeSessionHealth(
    state: TransportState,
    attemptContext: VpnAttemptContext,
    relayStage: RelayReadinessStage?,
    dataPlaneProofPending: Boolean = false,
): VpnSessionHealth = when (state) {
    is TransportState.Disconnected -> VpnSessionHealth.Idle
    is TransportState.Connecting, is TransportState.Disconnecting -> VpnSessionHealth.InProgress
    is TransportState.Reconnecting -> VpnSessionHealth.Reconnecting
    is TransportState.Error -> VpnSessionHealth.Failed(state.message)
    is TransportState.HandshakeFailed -> VpnSessionHealth.Failed("Handshake failed")
    is TransportState.Connected -> when (attemptContext) {
        is VpnAttemptContext.Direct -> if (dataPlaneProofPending) VpnSessionHealth.DataPlaneVerifying else VpnSessionHealth.DirectProtected
        is VpnAttemptContext.Relayed -> if (relayStage == RelayReadinessStage.END_TO_END_DATA_PLANE_OK) {
            VpnSessionHealth.RelayProtected
        } else {
            VpnSessionHealth.RelayHandshake(relayStage ?: RelayReadinessStage.INGRESS_HANDSHAKE_OK)
        }
    }
}

/**
 * H2-GATE - transports whose Connected alone never means Protected: only a
 * fresh B-WL7 VERIFIED from their own data-plane counters does. Hysteria2
 * only - its connect-time probe never touches the TUN -> tun2socks leg.
 */
fun requiresDataPlaneProof(kind: TransportKind?): Boolean = kind == TransportKind.HYSTERIA2
