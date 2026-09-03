package net.pocvpn.client.provisioning

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.controlplane.fetchThroughTrustedOrigins
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B8K4B - the ONE place POST /v1/xray-profile's result becomes (or does not
 * become) a persisted [net.pocvpn.client.identity.XrayProfile]. Reuses the
 * SAME activation credential and SAME existing device public key the caller
 * already used for POST /v1/activate - this class introduces no identity or
 * credential of its own, it only decides what to do with an
 * [XrayProfileResult].
 *
 * [XrayProfileRepository.saveProfile] is called in EXACTLY ONE branch below
 * (a validated [XrayProfileResult.Success]) - every other outcome
 * (network error, 401/403, 503, malformed body) returns without touching the
 * repository at all, so a previously saved valid profile is never
 * overwritten or deleted by a failed fetch.
 */
class XrayProfileProvisioner(
    private val repository: XrayProfileRepository,
    // B30 review fix (origin-discarding blocker) - non-null, defaults to
    // GERMANY (this codebase's own existing "Germany-default" convention -
    // see ProvisioningClient's 2-arg overloads). provision() ALWAYS routes
    // through fetchThroughTrustedOrigins/ControlPlaneOriginSetBuilder now -
    // a pre-B30 call site that doesn't care about gateway/origin still gets
    // exactly one real, correct origin (behaviorally identical to a single
    // direct call), rather than a second, parallel non-origin-aware code
    // path that could silently diverge from the real one. Declared BEFORE
    // fetchXrayProfile below so every pre-B30 call site using
    // trailing-lambda syntax for fetchXrayProfile - e.g.
    // `XrayProfileProvisioner(repo) { origin, pk, cred -> ... }` - keeps
    // binding that lambda to fetchXrayProfile, the last function-typed
    // parameter.
    private val gatewayId: ProductionGatewayId = ProductionGatewayId.GERMANY,
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
    // B30 review fix (origin-discarding blocker) - now ORIGIN-AWARE: the
    // default genuinely dials [net.pocvpn.client.controlplane.ControlPlaneOrigin.host],
    // never a fixed/pre-bound host - see MainViewModel's own
    // activationClient docs for the identical reasoning. A 2-origin
    // executor must actually reach two different hosts, never silently
    // repeat the same request under a different label.
    private val fetchXrayProfile: (origin: net.pocvpn.client.controlplane.ControlPlaneOrigin, publicKey: String, activationCredential: String) -> XrayProfileResult =
        { origin, publicKey, activationCredential -> ProvisioningClient.fetchXrayProfile(publicKey, activationCredential, origin.host) },
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome {
        val result = fetchThroughTrustedOrigins(
            gatewayId = gatewayId,
            diagnosticsRecorder = diagnosticsRecorder,
            classify = ::classifyXrayProfileResultFailure,
            fetch = { origin -> fetchXrayProfile(origin, publicKey, activationCredential) },
        )
        return when (result) {
            is XrayProfileResult.Success -> {
                repository.saveProfile(result.toXrayProfile())
                XrayProfileProvisioningOutcome.Saved
            }
            is XrayProfileResult.Unauthorized,
            is XrayProfileResult.Revoked,
            is XrayProfileResult.DeviceNotBound,
            -> XrayProfileProvisioningOutcome.AuthorizationFailed
            is XrayProfileResult.ServiceUnavailable,
            is XrayProfileResult.NetworkError,
            -> XrayProfileProvisioningOutcome.Unavailable
            is XrayProfileResult.MalformedResponse -> XrayProfileProvisioningOutcome.Malformed(result.reason)
        }
    }
}

/**
 * B30 review fix (blocker 2) - pure classification of [XrayProfileResult]
 * into the closed [ControlPlaneFailureReason] taxonomy, reused by
 * [fetchThroughTrustedOrigins]. `internal` so it is unit-testable directly.
 */
internal fun classifyXrayProfileResultFailure(result: XrayProfileResult): ControlPlaneFailureReason? = when (result) {
    is XrayProfileResult.Success -> null
    is XrayProfileResult.Unauthorized, is XrayProfileResult.Revoked, is XrayProfileResult.DeviceNotBound ->
        ControlPlaneFailureReason.AUTHORIZATION_REJECTED
    is XrayProfileResult.ServiceUnavailable -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
    is XrayProfileResult.NetworkError -> net.pocvpn.client.controlplane.classifyNetworkErrorMessage(result.message)
    is XrayProfileResult.MalformedResponse -> ControlPlaneFailureReason.MALFORMED_RESPONSE
}
