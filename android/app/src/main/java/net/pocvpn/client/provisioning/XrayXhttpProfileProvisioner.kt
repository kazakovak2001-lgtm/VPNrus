package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.controlplane.fetchThroughTrustedOrigins
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.identity.XrayXhttpProfileRepository
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B64 - the Direct/EXIT XHTTP counterpart of [XrayTlsProfileProvisioner]:
 * the ONE place POST /v1/xray-profile's `transport=xhttp` result becomes (or
 * does not become) a persisted
 * [XrayXhttpProfile][net.pocvpn.client.identity.XrayXhttpProfile]. Reuses
 * the SAME activation credential and SAME existing device public key as the
 * REALITY/TLS provisioners - no second identity, no new credential.
 */
class XrayXhttpProfileProvisioner(
    private val repository: XrayXhttpProfileRepository,
    private val gatewayId: ProductionGatewayId = ProductionGatewayId.GERMANY,
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
    private val fetchXrayXhttpProfile: (origin: net.pocvpn.client.controlplane.ControlPlaneOrigin, publicKey: String, activationCredential: String) -> XrayXhttpProfileResult =
        { origin, publicKey, activationCredential -> ProvisioningClient.fetchXrayXhttpProfile(publicKey, activationCredential, origin.host) },
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome {
        val result = fetchThroughTrustedOrigins(
            gatewayId = gatewayId,
            diagnosticsRecorder = diagnosticsRecorder,
            classify = ::classifyXrayXhttpProfileResultFailure,
            fetch = { origin -> fetchXrayXhttpProfile(origin, publicKey, activationCredential) },
        )
        return when (result) {
            is XrayXhttpProfileResult.Success -> {
                repository.saveProfile(result.toXrayXhttpProfile())
                XrayProfileProvisioningOutcome.Saved
            }
            is XrayXhttpProfileResult.Unauthorized,
            is XrayXhttpProfileResult.Revoked,
            is XrayXhttpProfileResult.DeviceNotBound,
            -> XrayProfileProvisioningOutcome.AuthorizationFailed
            is XrayXhttpProfileResult.ServiceUnavailable,
            is XrayXhttpProfileResult.NetworkError,
            -> XrayProfileProvisioningOutcome.Unavailable
            is XrayXhttpProfileResult.MalformedResponse -> XrayProfileProvisioningOutcome.Malformed(result.reason)
        }
    }
}

/** B64 - pure classification, mirrors [classifyXrayTlsProfileResultFailure]. `internal` so it is unit-testable directly. */
internal fun classifyXrayXhttpProfileResultFailure(result: XrayXhttpProfileResult): ControlPlaneFailureReason? = when (result) {
    is XrayXhttpProfileResult.Success -> null
    is XrayXhttpProfileResult.Unauthorized, is XrayXhttpProfileResult.Revoked, is XrayXhttpProfileResult.DeviceNotBound ->
        ControlPlaneFailureReason.AUTHORIZATION_REJECTED
    is XrayXhttpProfileResult.ServiceUnavailable -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
    is XrayXhttpProfileResult.NetworkError -> net.pocvpn.client.controlplane.classifyNetworkErrorMessage(result.message)
    is XrayXhttpProfileResult.MalformedResponse -> ControlPlaneFailureReason.MALFORMED_RESPONSE
}
