package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.XrayTlsProfileRepository

/**
 * B8O2 - the TLS/TCP counterpart of [XrayProfileProvisioner]: the ONE place
 * POST /v1/xray-profile's `transport=tls` result becomes (or does not
 * become) a persisted [XrayTlsProfile][net.pocvpn.client.identity.XrayTlsProfile].
 * Reuses the SAME activation credential and SAME existing device public key
 * as the REALITY provisioner - no second identity, no new credential.
 */
class XrayTlsProfileProvisioner(
    private val repository: XrayTlsProfileRepository,
    private val fetchXrayTlsProfile: (publicKey: String, activationCredential: String) -> XrayTlsProfileResult =
        ProvisioningClient::fetchXrayTlsProfile,
) {
    suspend fun provision(publicKey: String, activationCredential: String): XrayProfileProvisioningOutcome =
        when (val result = fetchXrayTlsProfile(publicKey, activationCredential)) {
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
