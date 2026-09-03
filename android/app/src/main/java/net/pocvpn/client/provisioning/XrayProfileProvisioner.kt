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
    // B30 review fix (blocker 2) - additive, both default to null (old,
    // single-call behavior, byte-for-byte unchanged for every pre-B30
    // test/call site). When [gatewayId] is set, provision() routes
    // [fetchXrayProfile] through the SAME TrustedOriginRequestExecutor/
    // ControlPlaneOriginSetBuilder net.pocvpn.client.controlplane
    // .ActivationResilienceCoordinator uses for activation - genuinely
    // wired through the generic executor, not only instrumented. Declared
    // BEFORE fetchXrayProfile below (not after) so every pre-B30 call site
    // using trailing-lambda syntax for fetchXrayProfile - e.g.
    // `XrayProfileProvisioner(repo) { pk, cred -> ... }` - keeps binding
    // that lambda to fetchXrayProfile, the last function-typed parameter.
    private val gatewayId: ProductionGatewayId? = null,
    private val diagnosticsRecorder: SupportDiagnosticsRecorder? = null,
    // Additive seam, same reasoning as MainViewModel's own activationClient
    // param: defaults to the real network call so production wiring is
    // byte-for-byte ProvisioningClient::fetchXrayProfile, while tests can
    // substitute a fake without a live HTTPS call.
    private val fetchXrayProfile: (publicKey: String, activationCredential: String) -> XrayProfileResult =
        ProvisioningClient::fetchXrayProfile,
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome {
        val gwId = gatewayId
        val result = if (gwId == null) {
            fetchXrayProfile(publicKey, activationCredential)
        } else {
            fetchThroughTrustedOrigins(
                gatewayId = gwId,
                diagnosticsRecorder = diagnosticsRecorder,
                classify = ::classifyXrayProfileResultFailure,
                fetch = { fetchXrayProfile(publicKey, activationCredential) },
            )
        }
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
