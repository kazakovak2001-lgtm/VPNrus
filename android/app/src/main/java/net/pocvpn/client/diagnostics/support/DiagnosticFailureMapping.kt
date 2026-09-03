package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.smartconnect.RestrictionClass

/**
 * B29 (task C) - pure mapping from every real, existing outcome type this
 * codebase already produces into the closed [DiagnosticFailureReason]
 * vocabulary a support bundle carries. Deliberately NEVER replaces
 * [VpnError]/[RelayFailureCategory]/[IngressActivationOutcome] - those stay
 * the real, authoritative outcome types everywhere else in this codebase;
 * this file only RE-LABELS them for one consumer (the support bundle).
 */
fun mapVpnErrorToFailureReason(error: VpnError): DiagnosticFailureReason = when (error) {
    VpnError.PermissionDenied -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.GatewayConfigurationMissing -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.InvalidGatewayConfiguration -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.BackendStartFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    is VpnError.BackendStopFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.NetworkUnavailable -> DiagnosticFailureReason.NETWORK_UNAVAILABLE
    VpnError.ReconnectExhausted -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    is VpnError.ConfigurationMappingFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.AlreadyInProgress -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.HandshakeTimeout -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    VpnError.SplitTunnelingNoAppsSelected -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.NoCandidateAvailable -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.UnsupportedTransportSelected -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.RestrictedNetworkNoViableRelay -> DiagnosticFailureReason.RESTRICTED_NETWORK_NO_VIABLE_RELAY
}

fun mapRelayFailureCategoryToFailureReason(category: RelayFailureCategory): DiagnosticFailureReason = when (category) {
    RelayFailureCategory.INGRESS_UNREACHABLE -> DiagnosticFailureReason.INGRESS_UNREACHABLE
    RelayFailureCategory.INGRESS_HANDSHAKE_FAILED -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    RelayFailureCategory.UPSTREAM_EXIT_HANDSHAKE_FAILED -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RelayFailureCategory.RELAY_AUTH_FAILED -> DiagnosticFailureReason.ACTIVATION_FAILED
    RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED -> DiagnosticFailureReason.RELAY_END_TO_END_PROOF_FAILED
    RelayFailureCategory.PROFILE_NOT_PROVISIONED -> DiagnosticFailureReason.INGRESS_PROFILE_REQUIRED
    RelayFailureCategory.PROFILE_MISMATCH -> DiagnosticFailureReason.INGRESS_PROFILE_MISMATCH
    RelayFailureCategory.PROFILE_EXPIRED -> DiagnosticFailureReason.INGRESS_PROFILE_REQUIRED
    RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED -> DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE
}

/** Returns null for [IngressActivationOutcome.Saved] (not a failure). */
fun mapIngressActivationOutcomeToFailureReason(outcome: IngressActivationOutcome): DiagnosticFailureReason? = when (outcome) {
    is IngressActivationOutcome.Saved -> null
    IngressActivationOutcome.AuthorizationFailed -> DiagnosticFailureReason.ACTIVATION_FAILED
    IngressActivationOutcome.Unavailable -> DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE
    IngressActivationOutcome.UnsupportedTransport -> DiagnosticFailureReason.ACTIVATION_FAILED
    is IngressActivationOutcome.Mismatched -> DiagnosticFailureReason.INGRESS_PROFILE_MISMATCH
}

/**
 * B29 - the ONE place [RestrictionClass.POSSIBLE_HARD_WHITELIST] itself
 * (not merely "no viable relay" - see [mapVpnErrorToFailureReason]'s
 * [VpnError.RestrictedNetworkNoViableRelay] case for that narrower one)
 * becomes a support-bundle-facing failure reason, for a session that never
 * even reached the point of building combined attempts (e.g. NO_NETWORK/
 * CAPTIVE_PORTAL take priority - see [net.pocvpn.client.smartconnect
 * .RestrictionClassifier]'s own priority order, checked here in the SAME
 * order for consistency). Returns null for every class that is not itself
 * failure-worthy on its own.
 */
fun mapRestrictionClassToFailureReason(restrictionClass: RestrictionClass): DiagnosticFailureReason? = when (restrictionClass) {
    RestrictionClass.NO_NETWORK -> DiagnosticFailureReason.NETWORK_UNAVAILABLE
    RestrictionClass.CAPTIVE_PORTAL -> DiagnosticFailureReason.CAPTIVE_PORTAL
    RestrictionClass.GATEWAY_HTTPS_UNREACHABLE -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RestrictionClass.POSSIBLE_HARD_WHITELIST -> DiagnosticFailureReason.POSSIBLE_HARD_WHITELIST
    RestrictionClass.INTERNET_NOT_VALIDATED,
    RestrictionClass.NETWORK_RECOVERING,
    RestrictionClass.NO_RESTRICTION_OBSERVED,
    RestrictionClass.UNKNOWN,
    -> null
}
