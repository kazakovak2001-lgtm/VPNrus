package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.Hysteria2Credential
import net.pocvpn.client.identity.Hysteria2CredentialRepository
import net.pocvpn.client.identity.Hysteria2CredentialValidationResult
import net.pocvpn.client.identity.Hysteria2CredentialValidator
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding

/**
 * B46-4A - the real Android client control-plane path for Hysteria2: POST
 * /v1/hysteria-profile -> validate the response actually names the endpoint
 * THIS request targeted -> validate its own credential content -> construct
 * an endpoint-bound [Hysteria2Credential] -> save through
 * [Hysteria2CredentialRepository] -> typed outcome. No Smart Connect changes
 * belong inside this provisioner (per task instruction) - it never touches
 * `TransportRegistry`/`MainViewModel.buildTransportRegistry`.
 *
 * [endpointBinding] is the caller's own already-pinned fact (from the signed
 * manifest) - NEVER re-derived from the HTTP response. [provision]
 * cross-checks the response's own `server_address`/`server_port` against
 * [endpointBinding]'s host/port and fails closed with [Hysteria2ProvisioningOutcome.Mismatched]
 * on any disagreement - mirrors [net.pocvpn.client.relay.IngressProfileProvisioner]'s
 * own "pinned-fact mismatch fails closed" discipline exactly.
 *
 * NO RAW ACTIVATION CREDENTIAL AS HYSTERIA AUTH (per task instruction):
 * [activationCredential] authorizes this HTTP call only - it is never stored,
 * never reused as [Hysteria2Credential.authSecret]. The distinct
 * `auth_secret` the server mints in its own response body is the only value
 * ever written into [Hysteria2CredentialRepository].
 */
class Hysteria2ProfileProvisioner(
    private val repository: Hysteria2CredentialRepository,
    private val fetchHysteria2Profile: (publicKey: String, bearerToken: String, endpointHost: String) -> Hysteria2ProfileResult =
        ProvisioningClient::fetchHysteria2Profile,
) {
    suspend fun provision(
        endpointId: EndpointId,
        endpointBinding: EndpointTransportBinding,
        publicKey: String,
        activationCredential: String,
    ): Hysteria2ProvisioningOutcome {
        val result = fetchHysteria2Profile(publicKey, activationCredential, endpointBinding.host)
        return when (result) {
            is Hysteria2ProfileResult.Success -> {
                if (result.serverAddress != endpointBinding.host || result.serverPort != endpointBinding.port) {
                    return Hysteria2ProvisioningOutcome.Mismatched(
                        "response server ${result.serverAddress}:${result.serverPort} does not match the pinned binding ${endpointBinding.host}:${endpointBinding.port}",
                    )
                }
                val validated = Hysteria2CredentialValidator.validate(endpointId, result.authSecret, result.obfuscationSecret)
                val credential = when (validated) {
                    is Hysteria2CredentialValidationResult.Valid -> validated.credential
                    Hysteria2CredentialValidationResult.BlankAuthSecret -> return Hysteria2ProvisioningOutcome.CredentialRejected("server returned a blank auth secret")
                    Hysteria2CredentialValidationResult.AuthSecretTooLong -> return Hysteria2ProvisioningOutcome.CredentialRejected("server's auth secret exceeds the max accepted length")
                    Hysteria2CredentialValidationResult.BlankObfuscationSecret -> return Hysteria2ProvisioningOutcome.CredentialRejected("server returned a blank obfuscation secret")
                    Hysteria2CredentialValidationResult.ObfuscationSecretTooLong -> return Hysteria2ProvisioningOutcome.CredentialRejected("server's obfuscation secret exceeds the max accepted length")
                }
                repository.storeCredential(credential)
                Hysteria2ProvisioningOutcome.Saved
            }
            Hysteria2ProfileResult.Unauthorized,
            Hysteria2ProfileResult.Revoked,
            Hysteria2ProfileResult.Expired,
            Hysteria2ProfileResult.DeviceNotBound,
            -> Hysteria2ProvisioningOutcome.AuthorizationFailed
            Hysteria2ProfileResult.ServiceUnavailable,
            is Hysteria2ProfileResult.NetworkError,
            -> Hysteria2ProvisioningOutcome.Unavailable
            is Hysteria2ProfileResult.MalformedResponse -> Hysteria2ProvisioningOutcome.Mismatched(result.reason)
        }
    }
}

/** B46-4A - the typed result of one [Hysteria2ProfileProvisioner.provision] attempt. Mirrors `IngressActivationOutcome`'s own shape. */
sealed class Hysteria2ProvisioningOutcome {
    object Saved : Hysteria2ProvisioningOutcome()
    object AuthorizationFailed : Hysteria2ProvisioningOutcome()
    object Unavailable : Hysteria2ProvisioningOutcome()
    data class Mismatched(val reason: String) : Hysteria2ProvisioningOutcome()
    data class CredentialRejected(val reason: String) : Hysteria2ProvisioningOutcome()
}
