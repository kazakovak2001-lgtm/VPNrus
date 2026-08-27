package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind

/** Output of SmartConnectDecisionEngine - never a VpnTransport itself, only a decision about which kind to use. */
sealed class TransportSelectionDecision {
    data class SelectTransport(val kind: TransportKind) : TransportSelectionDecision()
    object NoTransportAvailable : TransportSelectionDecision()

    /** Reserved for when a future probe-before-select flow exists - not produced by Phase 2A logic yet. */
    object ProbeRequired : TransportSelectionDecision()

    /** User's MANUAL preference named a transport that is not AVAILABLE. */
    object UserPolicyBlocked : TransportSelectionDecision()
    object NetworkUnavailable : TransportSelectionDecision()
}
