package net.pocvpn.client.smartconnect

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.TransportState

/**
 * B8I8 - the ONE place "should this already-completed AWG attempt fall back
 * to Xray" is decided. Pure/no I/O, no coroutines - never touches
 * VpnController/VpnTransport itself, only interprets the ALREADY-observed
 * outcome of an attempt Smart Connect (SmartConnectCandidateSelector - THE
 * one selection authority, untouched by this class) already made and
 * MainViewModel already executed. Deliberately NOT part of
 * TransportOrchestrator (which only ever resolves a kind into an instance,
 * never decides a retry - see its own docs) and NOT a second lifecycle
 * state machine inside VpnController - this is a narrow, stateless
 * eligibility check MainViewModel consults once per connect() attempt.
 *
 * [awgState]/[awgError] are always set together, atomically, by
 * VpnController.doConnectAttempt() for every branch (see that function's
 * own code) - by the time controller.connect(resolution) (a suspend call)
 * returns, both truthfully describe THIS attempt's own outcome, never a
 * stale value left over from an earlier attempt. Both are required (not
 * just [awgError] alone) specifically so a caller that forgets to check the
 * CURRENT state can't accidentally treat a stale VpnError from a PRIOR
 * failed attempt as if it applied to a brand new, actually-successful one.
 */
object AwgXrayFailoverPolicy {

    fun isEligibleForXrayFallback(
        initialKind: TransportKind,
        preference: UserTransportPreference,
        awgState: TransportState,
        awgError: VpnError?,
        xrayAvailable: Boolean,
    ): Boolean {
        // Nothing to "fall back FROM" unless the initial Smart Connect
        // selection (and therefore the attempt just executed) was AWG
        // itself - a direct XRAY_REALITY selection never triggers this.
        if (initialKind != TransportKind.AMNEZIA_WG) return false

        // A user who pinned a specific transport gets exactly that
        // transport, success or failure - never a silent substitute. This
        // also covers "Manual AMNEZIA_WG -> no automatic Xray fallback" and
        // "Manual XRAY_REALITY -> no AWG attempt in the first place" (the
        // latter is already unreachable here via the initialKind check
        // above, but excluded again here for clarity/defense in depth).
        if (preference is UserTransportPreference.Manual) return false

        if (!xrayAvailable) return false

        // Only a genuine TERMINAL failure of THIS attempt is eligible -
        // Connected (success), Connecting/Disconnected/Disconnecting (not a
        // completed attempt at all - e.g. still awaiting a VPN permission
        // prompt, or a user-initiated disconnect/cancellation), and
        // Reconnecting are all excluded by this alone.
        if (awgState !is TransportState.HandshakeFailed && awgState !is TransportState.Error) return false

        // The exact, enumerated "real AWG connection failure" categories -
        // never a catch-all "any Error". Every other VpnError
        // doConnectAttempt can produce (GatewayConfigurationMissing,
        // InvalidGatewayConfiguration, SplitTunnelingNoAppsSelected,
        // ConfigurationMappingFailure, PermissionDenied, AlreadyInProgress) -
        // and every rejectPreflight() error (NoCandidateAvailable,
        // UnsupportedTransportSelected) - represents a preflight/local-
        // configuration/permission problem, never a real connection
        // failure, and is deliberately NOT eligible for fallback.
        return when (awgError) {
            is VpnError.HandshakeTimeout -> true
            is VpnError.BackendStartFailure -> true
            // Recorded only by VpnController.reconnectLoop() - an async,
            // post-Connected retry-exhaustion signal for an attempt that
            // already succeeded once, never the outcome of THIS (the
            // just-executed, still-pending-first-connect) attempt. Listed
            // explicitly rather than folded into the catch-all below so this
            // exclusion is a deliberate, reviewable decision, not an
            // accident of "every other VpnError happens to be false".
            is VpnError.ReconnectExhausted -> false
            else -> false
        }
    }
}
