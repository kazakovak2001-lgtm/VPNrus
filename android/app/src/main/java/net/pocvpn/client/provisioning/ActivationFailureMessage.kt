package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.controlplane.classifyNetworkErrorMessage

/**
 * B30 (task 6) - "First-run failure UX": a non-technical, fixed sentence
 * for every failing [ProvisioningUiState], reused by
 * [net.pocvpn.client.MainViewModel.activationFailureMessage]. `internal`
 * (not private) so this pure mapping is directly unit-testable - the whole
 * point of task 6 ("do not show raw exceptions, hostnames, ports, TLS
 * errors, or stack traces") is a property of THIS function, provable
 * without a live network call or a full MainViewModel instance.
 *
 * Every branch here returns a FIXED string literal - never string
 * interpolation of [ProvisioningUiState.Error.message] or any other
 * caller-supplied text - which is what makes "never leaks a raw exception"
 * true by construction rather than by convention.
 */
internal fun friendlyActivationFailureMessage(state: ProvisioningUiState): String? = when (state) {
    is ProvisioningUiState.Idle, is ProvisioningUiState.Provisioning, is ProvisioningUiState.Success -> null
    is ProvisioningUiState.Unauthorized -> "That activation code wasn't accepted. Check the code and try again."
    is ProvisioningUiState.Revoked -> "This activation code is no longer valid. Ask for a new one."
    is ProvisioningUiState.Expired -> "This activation code has expired. Ask for a new one."
    is ProvisioningUiState.DeviceLimitReached -> "This activation code has already reached its device limit."
    // B30 (task 6) - the required copy, verbatim, for every other failure
    // shape (network error, malformed response, service unavailable, bad
    // request) - deliberately the SAME single sentence regardless of which
    // one occurred, since none of those distinctions are something a
    // non-technical user can act on.
    is ProvisioningUiState.Error ->
        "VPN setup could not be completed on this network. Try another network or send diagnostics."
}

/**
 * B30 (task 8/9) - pure classification of a raw [ProvisioningResult] into
 * the closed [ControlPlaneFailureReason] taxonomy for diagnostics,
 * reused by both [net.pocvpn.client.MainViewModel.activateDevice]'s own
 * diagnostics hook and [net.pocvpn.client.controlplane.ActivationResilienceCoordinator] -
 * one classification, never two independently-maintained copies. Returns
 * null for [ProvisioningResult.Success] (not a failure).
 */
fun classifyProvisioningResultFailure(result: ProvisioningResult): ControlPlaneFailureReason? = when (result) {
    is ProvisioningResult.Success -> null
    is ProvisioningResult.Unauthorized, is ProvisioningResult.Revoked,
    is ProvisioningResult.Expired, is ProvisioningResult.DeviceLimitReached,
    is ProvisioningResult.BadRequest,
    -> ControlPlaneFailureReason.AUTHORIZATION_REJECTED
    is ProvisioningResult.ServiceUnavailable -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
    is ProvisioningResult.MalformedResponse -> ControlPlaneFailureReason.MALFORMED_RESPONSE
    is ProvisioningResult.NetworkError -> classifyNetworkErrorMessage(result.message)
}
