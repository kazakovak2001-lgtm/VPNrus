package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.vpn.TransportState

/**
 * B16 - the ONE place "should this already-completed automatic-gateway
 * attempt advance to the NEXT ranked [GatewayAttemptCandidate]" is decided.
 * Pure/no I/O, mirrors [AwgXrayFailoverPolicy]'s own terminal-failure
 * discipline (same distinct, enumerated failure categories - task
 * requirement 3's "distinct failure conditions", never a catch-all "any
 * Error") but deliberately does NOT gate on [initialKind]/[preference]/
 * [xrayAvailable] the way that policy does - those questions are about
 * ONE gateway's own intra-gateway AWG->Xray fallback, a completely
 * different, still-untouched mechanism (see that class's own docs).
 * Automatic cross-gateway advancement is eligible for a terminal failure of
 * ANY transport kind, on ANY gateway, as long as the caller is genuinely in
 * automatic gateway-selection mode (checked by the caller, never here -
 * this policy has no gateway-mode concept of its own).
 */
object AutoGatewayFailoverPolicy {

    fun isEligibleForNextCandidate(state: TransportState, error: VpnError?): Boolean {
        // Only a genuine TERMINAL failure of THIS attempt is eligible -
        // Connected (success), Connecting/Disconnected/Disconnecting (not a
        // completed attempt at all), and Reconnecting are all excluded.
        if (state !is TransportState.HandshakeFailed && state !is TransportState.Error) return false

        return when (error) {
            is VpnError.HandshakeTimeout -> true
            is VpnError.BackendStartFailure -> true
            // An async, post-Connected retry-exhaustion signal for an
            // attempt that already succeeded once - never the outcome of
            // THIS (the just-executed, still-establishing) attempt. Once a
            // candidate has genuinely connected, requirement 8 ("do not
            // silently change gateways while the tunnel is healthy") governs,
            // not this policy.
            is VpnError.ReconnectExhausted -> false
            else -> false
        }
    }
}
