package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayProfileRepository

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
    // Additive seam, same reasoning as MainViewModel's own activationClient
    // param: defaults to the real network call so production wiring is
    // byte-for-byte ProvisioningClient::fetchXrayProfile, while tests can
    // substitute a fake without a live HTTPS call.
    private val fetchXrayProfile: (publicKey: String, activationCredential: String) -> XrayProfileResult =
        ProvisioningClient::fetchXrayProfile,
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome =
        when (val result = fetchXrayProfile(publicKey, activationCredential)) {
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
