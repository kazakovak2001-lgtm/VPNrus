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
}
