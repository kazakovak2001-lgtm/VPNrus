package net.pocvpn.client.provisioning

/** B8B3A/B8C2 - the visible states the debug provisioning/activation UI must show. */
sealed class ProvisioningUiState {
    object Idle : ProvisioningUiState()
    object Provisioning : ProvisioningUiState()
    data class Success(val result: ProvisioningResult.Success) : ProvisioningUiState()
    object Unauthorized : ProvisioningUiState()
    // B8C2 - distinct activation-only outcomes (see ProvisioningResult's own docs).
    object Revoked : ProvisioningUiState()
    object Expired : ProvisioningUiState()
    object DeviceLimitReached : ProvisioningUiState()
    data class Error(val message: String) : ProvisioningUiState()

    /**
     * B36 - every known bootstrap candidate (Frankfurt/Stockholm) failed to
     * produce a usable pre-activation tunnel, so the activation request was
     * never even attempted (task requirement 1's "explicit
     * bootstrap-unavailable state" / "do not show misleading 'Invalid
     * activation' for pure network failure"). Deliberately distinct from
     * [Unauthorized] (a real credential rejection) and from [Error] (a
     * network/service failure of the activation request ITSELF, which DID
     * reach the control plane) - see
     * [net.pocvpn.client.bootstrap.BootstrapActivationOutcome] for the full
     * bootstrap-assisted outcome vocabulary this maps from.
     */
    object BootstrapUnavailable : ProvisioningUiState()
}
