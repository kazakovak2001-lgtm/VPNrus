package net.pocvpn.client.bootstrap

import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B36 (task requirement 10) - the closed outcome vocabulary a bootstrap-
 * assisted activation attempt can reach, distinguishing exactly the cases
 * task requirement 10 requires: invalid credential, bootstrap unavailable,
 * network/provisioning unavailable, expired/device-limit, and success.
 * Deliberately mirrors [ProvisioningUiState]'s own existing distinctions
 * (never re-derives them differently) plus the two states only a
 * bootstrap-assisted attempt can reach ([BootstrapUnavailable],
 * [ProfilePersistFailed]).
 */
sealed class BootstrapActivationOutcome {
    data class Success(val gatewayId: ProductionGatewayId, val result: ProvisioningResult.Success) : BootstrapActivationOutcome()

    /** No persisted/provisioned profile check was needed - the caller already had one; the existing manual flow should be used directly instead. */
    object AlreadyProvisioned : BootstrapActivationOutcome()

    /** Every known bootstrap candidate failed to produce a usable tunnel - never attempted the activation request at all (task requirement 9's case C). */
    data class BootstrapUnavailable(val attempted: List<ProductionGatewayId>) : BootstrapActivationOutcome()

    object Unauthorized : BootstrapActivationOutcome()
    object Revoked : BootstrapActivationOutcome()
    object Expired : BootstrapActivationOutcome()
    object DeviceLimitReached : BootstrapActivationOutcome()

    /** Bootstrap connected and the activation request itself failed for a network/service reason - never confused with [Unauthorized] (task requirement 9's case E). */
    object NetworkOrProvisioningError : BootstrapActivationOutcome()

    /** The wire-level activation response was accepted, but this device still has no persisted/provisioned identity for [gatewayId] afterward - fail closed rather than report success (task requirement 9's own persistence-failure case). */
    data class ProfilePersistFailed(val gatewayId: ProductionGatewayId) : BootstrapActivationOutcome()
}

/**
 * B36 - the single top-level owner of "bootstrap tunnel, then existing
 * activation, through it" (task requirement 8). Composes
 * [BootstrapTunnelController] (bootstrap lifecycle only) with the caller's
 * existing activation machinery ([activate], production-wired to
 * [net.pocvpn.client.MainViewModel.performActivation] - the EXACT same
 * code path [net.pocvpn.client.MainViewModel.activateDevice] itself uses,
 * never a duplicate - see that function's own docs) - this class invents no
 * new activation/persistence logic of its own.
 *
 * State machine (task requirement 1):
 * `UNACTIVATED -> BOOTSTRAP_CONNECTING -> BOOTSTRAP_CONNECTED -> ACTIVATING
 * -> PROVISIONED -> bootstrap teardown` is realized as: check
 * [hasAnyProvisionedProfile] (skip straight to [BootstrapActivationOutcome.AlreadyProvisioned]
 * if true - task requirement 9's case F) -> [BootstrapTunnelController.connect]
 * (BOOTSTRAP_CONNECTING/BOOTSTRAP_CONNECTED/[BootstrapActivationOutcome.BootstrapUnavailable]) ->
 * [activate] (ACTIVATING) -> classify -> [BootstrapTunnelController.teardown]
 * (task requirement 9's "bootstrap teardown must complete before normal
 * connection transition" - teardown is always awaited here BEFORE this
 * function returns, on every outcome, success or failure alike) ->
 * PROVISIONED is the caller's own responsibility once this function returns
 * [BootstrapActivationOutcome.Success] (this class never itself flips
 * [net.pocvpn.client.vpn.config.ProfileSource], exactly like
 * [net.pocvpn.client.MainViewModel.performActivation] already owns that).
 */
class BootstrapActivationOrchestrator(
    private val tunnelController: BootstrapTunnelController,
    private val hasAnyProvisionedProfile: () -> Boolean,
    private val isGatewayProvisioned: (ProductionGatewayId) -> Boolean,
    private val activate: suspend (ProductionGatewayId, String) -> ProvisioningUiState,
    private val diagnostics: BootstrapDiagnosticsRecorder? = null,
) {
    suspend fun activateViaBootstrap(activationCredential: String): BootstrapActivationOutcome {
        if (hasAnyProvisionedProfile()) {
            return BootstrapActivationOutcome.AlreadyProvisioned
        }

        val bootstrapResult = tunnelController.connect()
        val connected = bootstrapResult as? BootstrapState.Connected
        if (connected == null) {
            val unavailable = bootstrapResult as? BootstrapState.Unavailable
            return BootstrapActivationOutcome.BootstrapUnavailable(unavailable?.attempted ?: emptyList())
        }

        val candidate = connected.candidate
        diagnostics?.recordActivationStarted(candidate)

        val uiState = try {
            activate(candidate, activationCredential)
        } catch (t: Throwable) {
            ProvisioningUiState.Error(t.message ?: "bootstrap-assisted activation failed")
        }

        val outcome = classify(candidate, uiState)
        diagnostics?.recordActivationResult(candidate, outcome::class.simpleName ?: "Unknown")

        // Task requirement 9 - teardown must complete before this function
        // returns (i.e. before the caller can expose a PROVISIONED/normal
        // connection state), regardless of the outcome above - a failed
        // activation must never leave the restricted bootstrap tunnel
        // running.
        tunnelController.teardown()

        if (outcome is BootstrapActivationOutcome.Success) {
            diagnostics?.recordProvisionedTransition(candidate)
        }
        return outcome
    }

    private fun classify(candidate: ProductionGatewayId, state: ProvisioningUiState): BootstrapActivationOutcome = when (state) {
        is ProvisioningUiState.Success ->
            if (isGatewayProvisioned(candidate)) {
                BootstrapActivationOutcome.Success(candidate, state.result)
            } else {
                BootstrapActivationOutcome.ProfilePersistFailed(candidate)
            }
        is ProvisioningUiState.Unauthorized -> BootstrapActivationOutcome.Unauthorized
        is ProvisioningUiState.Revoked -> BootstrapActivationOutcome.Revoked
        is ProvisioningUiState.Expired -> BootstrapActivationOutcome.Expired
        is ProvisioningUiState.DeviceLimitReached -> BootstrapActivationOutcome.DeviceLimitReached
        is ProvisioningUiState.Error -> BootstrapActivationOutcome.NetworkOrProvisioningError
        is ProvisioningUiState.BootstrapUnavailable -> BootstrapActivationOutcome.BootstrapUnavailable(emptyList())
        is ProvisioningUiState.Idle, is ProvisioningUiState.Provisioning ->
            BootstrapActivationOutcome.NetworkOrProvisioningError
    }
}
