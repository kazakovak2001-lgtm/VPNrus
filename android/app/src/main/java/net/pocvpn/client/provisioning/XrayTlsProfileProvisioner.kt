package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.controlplane.fetchThroughTrustedOrigins
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.identity.XrayTlsProfileRepository
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileProvisioner]: the ONE place
 * POST /v1/xray-profile's `transport=tls` result becomes (or does not
 * become) a persisted [XrayTlsProfile][net.pocvpn.client.identity.XrayTlsProfile].
 * Reuses the SAME activation credential and SAME existing device public key
 * as the REALITY provisioner - no second identity, no new credential.
 */
class XrayTlsProfileProvisioner(
    private val repository: XrayTlsProfileRepository,
    // B30 review fix (blocker 2) - additive, both default to null (old,
    // single-call behavior, byte-for-byte unchanged for every pre-B30
    // test/call site) - see XrayProfileProvisioner's own docs for the full
    // reasoning, identical here, including WHY these are declared before
    // fetchXrayTlsProfile (keeps trailing-lambda call sites binding to it).
    private val gatewayId: ProductionGatewayId? = null,
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
    private val fetchXrayTlsProfile: (publicKey: String, activationCredential: String) -> XrayTlsProfileResult =
        ProvisioningClient::fetchXrayTlsProfile,
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome {
        val gwId = gatewayId
        val result = if (gwId == null) {
            fetchXrayTlsProfile(publicKey, activationCredential)
        } else {
            fetchThroughTrustedOrigins(
                gatewayId = gwId,
                diagnosticsRecorder = diagnosticsRecorder,
                classify = ::classifyXrayTlsProfileResultFailure,
                fetch = { fetchXrayTlsProfile(publicKey, activationCredential) },
            )
        }
        return when (result) {
            is XrayTlsProfileResult.Success -> {
                repository.saveProfile(result.toXrayTlsProfile())
                XrayProfileProvisioningOutcome.Saved
            }
            is XrayTlsProfileResult.Unauthorized,
            is XrayTlsProfileResult.Revoked,
            is XrayTlsProfileResult.DeviceNotBound,
            -> XrayProfileProvisioningOutcome.AuthorizationFailed
            is XrayTlsProfileResult.ServiceUnavailable,
            is XrayTlsProfileResult.NetworkError,
            -> XrayProfileProvisioningOutcome.Unavailable
            is XrayTlsProfileResult.MalformedResponse -> XrayProfileProvisioningOutcome.Malformed(result.reason)
        }
    }
}

/** B30 review fix (blocker 2) - pure classification, mirrors [classifyXrayProfileResultFailure]. `internal` so it is unit-testable directly. */
internal fun classifyXrayTlsProfileResultFailure(result: XrayTlsProfileResult): ControlPlaneFailureReason? = when (result) {
    is XrayTlsProfileResult.Success -> null
    is XrayTlsProfileResult.Unauthorized, is XrayTlsProfileResult.Revoked, is XrayTlsProfileResult.DeviceNotBound ->
        ControlPlaneFailureReason.AUTHORIZATION_REJECTED
    is XrayTlsProfileResult.ServiceUnavailable -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
    is XrayTlsProfileResult.NetworkError -> net.pocvpn.client.controlplane.classifyNetworkErrorMessage(result.message)
    is XrayTlsProfileResult.MalformedResponse -> ControlPlaneFailureReason.MALFORMED_RESPONSE
}
