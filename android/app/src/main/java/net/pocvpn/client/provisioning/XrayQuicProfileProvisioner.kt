package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayQuicProfileRepository

/**
 * B21 - the QUIC counterpart of [XrayTlsProfileProvisioner]: the ONE place
 * POST /v1/xray-profile's `transport=quic` result becomes (or does not
 * become) a persisted [XrayQuicProfile][net.pocvpn.client.identity.XrayQuicProfile].
 * Reuses the SAME activation credential and SAME existing device public key
 * as the REALITY/TLS provisioners - no second identity, no new credential.
 */
class XrayQuicProfileProvisioner(
    private val repository: XrayQuicProfileRepository,
    private val fetchXrayQuicProfile: (publicKey: String, activationCredential: String) -> XrayQuicProfileResult =
        ProvisioningClient::fetchXrayQuicProfile,
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome =
        when (val result = fetchXrayQuicProfile(publicKey, activationCredential)) {
            is XrayQuicProfileResult.Success -> {
                repository.saveProfile(result.toXrayQuicProfile())
                XrayProfileProvisioningOutcome.Saved
            }
            is XrayQuicProfileResult.Unauthorized,
            is XrayQuicProfileResult.Revoked,
            is XrayQuicProfileResult.DeviceNotBound,
            -> XrayProfileProvisioningOutcome.AuthorizationFailed
            is XrayQuicProfileResult.ServiceUnavailable,
            is XrayQuicProfileResult.NetworkError,
            -> XrayProfileProvisioningOutcome.Unavailable
            is XrayQuicProfileResult.MalformedResponse -> XrayProfileProvisioningOutcome.Malformed(result.reason)
        }
}
