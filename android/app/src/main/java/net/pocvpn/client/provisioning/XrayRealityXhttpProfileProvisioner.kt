package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.controlplane.fetchThroughTrustedOrigins
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.identity.XrayRealityXhttpProfileRepository
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * The REALITY + XHTTP counterpart of [XrayXhttpProfileProvisioner]: the one
 * place POST /v1/xray-profile's `transport=reality-xhttp` result becomes (or
 * does not become) a persisted profile. Same activation credential, same
 * device public key, same trusted-origin fetch - no second identity.
 */
class XrayRealityXhttpProfileProvisioner(
    private val repository: XrayRealityXhttpProfileRepository,
    private val gatewayId: ProductionGatewayId,
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
    private val fetchProfile: (origin: net.pocvpn.client.controlplane.ControlPlaneOrigin, publicKey: String, activationCredential: String) -> XrayRealityXhttpProfileResult =
        { origin, publicKey, activationCredential -> ProvisioningClient.fetchXrayRealityXhttpProfile(publicKey, activationCredential, origin.host) },
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome {
        val result = fetchThroughTrustedOrigins(
            gatewayId = gatewayId,
            diagnosticsRecorder = diagnosticsRecorder,
            classify = ::classifyXrayRealityXhttpProfileResultFailure,
            fetch = { origin -> fetchProfile(origin, publicKey, activationCredential) },
        )
        return when (result) {
            is XrayRealityXhttpProfileResult.Success -> {
                repository.saveProfile(result.toXrayRealityXhttpProfile())
                XrayProfileProvisioningOutcome.Saved
            }
            is XrayRealityXhttpProfileResult.Unauthorized,
            is XrayRealityXhttpProfileResult.Revoked,
            is XrayRealityXhttpProfileResult.DeviceNotBound,
            -> XrayProfileProvisioningOutcome.AuthorizationFailed
            is XrayRealityXhttpProfileResult.ServiceUnavailable,
            is XrayRealityXhttpProfileResult.NetworkError,
            -> XrayProfileProvisioningOutcome.Unavailable
            is XrayRealityXhttpProfileResult.MalformedResponse -> XrayProfileProvisioningOutcome.Malformed(result.reason)
        }
    }
}

/** Pure classification, mirrors [classifyXrayXhttpProfileResultFailure]. */
internal fun classifyXrayRealityXhttpProfileResultFailure(result: XrayRealityXhttpProfileResult): ControlPlaneFailureReason? = when (result) {
    is XrayRealityXhttpProfileResult.Success -> null
    is XrayRealityXhttpProfileResult.Unauthorized, is XrayRealityXhttpProfileResult.Revoked, is XrayRealityXhttpProfileResult.DeviceNotBound ->
        ControlPlaneFailureReason.AUTHORIZATION_REJECTED
    is XrayRealityXhttpProfileResult.ServiceUnavailable -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
    is XrayRealityXhttpProfileResult.NetworkError -> net.pocvpn.client.controlplane.classifyNetworkErrorMessage(result.message)
    is XrayRealityXhttpProfileResult.MalformedResponse -> ControlPlaneFailureReason.MALFORMED_RESPONSE
}
