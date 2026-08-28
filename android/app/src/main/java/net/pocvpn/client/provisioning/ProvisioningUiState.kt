package net.pocvpn.client.provisioning

/** B8B3A - the four visible states the debug provisioning UI must show. */
sealed class ProvisioningUiState {
    object Idle : ProvisioningUiState()
    object Provisioning : ProvisioningUiState()
    data class Success(val result: ProvisioningResult.Success) : ProvisioningUiState()
    object Unauthorized : ProvisioningUiState()
    data class Error(val message: String) : ProvisioningUiState()
}
