package net.pocvpn.client.ui

import net.pocvpn.client.activation.ActivationPackageRejectionKind
import net.pocvpn.client.activation.ActivationPackageUiState

/**
 * B56-5 - user-facing copy for the activation-package flow, same
 * hardcoded-product-copy convention as [toActivationErrorText]. Never
 * includes any package content, credential, key id or reason string - only
 * a fixed sentence per category. `null` = nothing to show (in progress,
 * success, or [ActivationPackageUiState.ActivationFailed], whose specific
 * server-side reason is already shown via ProvisioningUiState).
 */
fun ActivationPackageUiState.toActivationPackageMessage(): String? = when (this) {
    ActivationPackageUiState.Idle,
    ActivationPackageUiState.Verifying,
    is ActivationPackageUiState.Activating,
    is ActivationPackageUiState.Succeeded,
    ActivationPackageUiState.ActivationFailed -> null
    is ActivationPackageUiState.NetworkRequired -> "Activation package verified. Network connection is required to finish activation."
    ActivationPackageUiState.Unavailable -> "Activation packages are not supported in this build."
    is ActivationPackageUiState.Rejected -> when (kind) {
        ActivationPackageRejectionKind.PACKAGE_MALFORMED,
        ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_MISMATCH,
        ActivationPackageRejectionKind.BOOTSTRAP_BUNDLE_INVALID -> "Activation package is invalid."
        ActivationPackageRejectionKind.PACKAGE_VERSION_UNSUPPORTED,
        ActivationPackageRejectionKind.LEVEL2_NOT_SUPPORTED -> "This activation package requires a newer app version."
        ActivationPackageRejectionKind.SIGNATURE_INVALID,
        ActivationPackageRejectionKind.ISSUER_UNKNOWN -> "Activation package is not trusted."
        ActivationPackageRejectionKind.EXPIRED -> "Activation package has expired."
        ActivationPackageRejectionKind.NOT_YET_VALID -> "Activation package is not valid yet."
        ActivationPackageRejectionKind.CLOCK_UNCERTAIN -> "Check your device date and time, then try again."
        ActivationPackageRejectionKind.ALREADY_REDEEMED -> "Activation package was already used."
    }
}

/** True while the package flow owns the activation screen's "submitting" state. */
fun ActivationPackageUiState.isInProgress(): Boolean =
    this is ActivationPackageUiState.Verifying || this is ActivationPackageUiState.Activating

/**
 * The activation screen's single error slot: package-specific copy only
 * while the field holds package text (so a stale package error never
 * masks a later raw-credential attempt), otherwise the existing
 * ProvisioningUiState copy - which also carries the server's answer
 * (revoked/expired/device limit) for a package that reached activation.
 */
fun activationErrorText(
    fieldText: String,
    packageState: ActivationPackageUiState,
    provisioningState: net.pocvpn.client.provisioning.ProvisioningUiState,
): String? {
    val packageMessage = if (net.pocvpn.client.activation.ActivationPackageParser.looksLikePackageText(fieldText)) {
        packageState.toActivationPackageMessage()
    } else {
        null
    }
    return packageMessage ?: provisioningState.toActivationErrorText()
}
