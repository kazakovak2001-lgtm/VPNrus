package net.pocvpn.client.provisioning

import net.pocvpn.client.identity.Hysteria2Credential
import net.pocvpn.client.identity.Hysteria2CredentialRepository
import net.pocvpn.client.identity.Hysteria2CredentialValidationResult
import net.pocvpn.client.identity.Hysteria2CredentialValidator
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.SignedTransportProfile
import net.pocvpn.client.reachability.SignedTransportProfileReadResult
import net.pocvpn.client.reachability.signedTransportProfile

/**
 * B46-4A - the real Android client control-plane path for Hysteria2: POST
 * /v1/hysteria-profile -> validate the response actually names the endpoint
 * THIS request targeted AND agrees with the already-trusted signed profile
 * -> validate its own credential content -> construct an endpoint-bound
 * [Hysteria2Credential] -> save through [Hysteria2CredentialRepository] ->
 * typed outcome. No Smart Connect changes belong inside this provisioner
 * (per task instruction) - it never touches `TransportRegistry`/
 * `MainViewModel.buildTransportRegistry`.
 *
 * B46-4A review fix (Finding 3/Finding 5) - [provision] now requires a real,
 * currently-trusted, typed [SignedTransportProfile.Hysteria2] for
 * [endpointBinding] BEFORE it ever calls the network - a Legacy/missing/
 * invalid/wrong-kind profile fails closed as [Hysteria2ProvisioningOutcome.NoTrustedBinding]
 * without dialing any host (never "provisioning against an arbitrary
 * host"). Once that trusted profile is resolved, EVERY public fact the
 * server's response claims - `server_address`, `server_port`, `sni`,
 * `obfuscation_mode` - is cross-checked against it; the control-plane
 * response is authority for SECRET material only (`auth_secret`,
 * `obfuscation_secret`), never for public routing/policy facts. Mirrors
 * [net.pocvpn.client.relay.IngressProfileProvisioner]'s own "pinned-fact
 * mismatch fails closed" discipline exactly.
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
        val trustedProfile = when (val read = endpointBinding.signedTransportProfile(endpointId)) {
            is SignedTransportProfileReadResult.Parsed -> (read.profile as? SignedTransportProfile.Hysteria2)?.profile
                ?: return Hysteria2ProvisioningOutcome.NoTrustedBinding("no typed Hysteria2 signed profile for endpoint ${endpointId.value} (legacy/wrong-kind binding)")
            SignedTransportProfileReadResult.Missing -> return Hysteria2ProvisioningOutcome.NoTrustedBinding("signed Hysteria2 profile missing for endpoint ${endpointId.value}")
            SignedTransportProfileReadResult.Unsupported -> return Hysteria2ProvisioningOutcome.NoTrustedBinding("signed Hysteria2 profile version unsupported for endpoint ${endpointId.value}")
            SignedTransportProfileReadResult.Invalid -> return Hysteria2ProvisioningOutcome.NoTrustedBinding("signed Hysteria2 profile invalid for endpoint ${endpointId.value}")
        }

        val result = fetchHysteria2Profile(publicKey, activationCredential, endpointBinding.host)
        return when (result) {
            is Hysteria2ProfileResult.Success -> {
                if (result.serverAddress != endpointBinding.host || result.serverPort != endpointBinding.port) {
                    return Hysteria2ProvisioningOutcome.Mismatched(
                        "response server ${result.serverAddress}:${result.serverPort} does not match the pinned binding ${endpointBinding.host}:${endpointBinding.port}",
                    )
                }
                if (result.sni != trustedProfile.sni) {
                    return Hysteria2ProvisioningOutcome.Mismatched(
                        "response sni '${result.sni}' does not match the trusted signed profile's sni '${trustedProfile.sni}'",
                    )
                }
                if (result.obfuscationMode != trustedProfile.obfuscationMode) {
                    return Hysteria2ProvisioningOutcome.Mismatched(
                        "response obfuscationMode '${result.obfuscationMode}' does not match the trusted signed profile's obfuscationMode '${trustedProfile.obfuscationMode}'",
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
                // B46-4A review fix (Finding 3) - the trusted signed mode is
                // the ONLY authority Hysteria2VpnService consults at connect
                // time, but this provisioner still refuses to SAVE a
                // credential that already disagrees with it (e.g. a NONE
                // profile whose response somehow carried an obfuscation
                // secret) - never persist a credential that could not pass
                // the service's own runtime consistency gate.
                val credentialHasObfuscationSecret = credential.obfuscationSecret != null
                val credentialConsistent = when (trustedProfile.obfuscationMode) {
                    "NONE" -> !credentialHasObfuscationSecret
                    "SALAMANDER" -> credentialHasObfuscationSecret
                    else -> false
                }
                if (!credentialConsistent) {
                    return Hysteria2ProvisioningOutcome.CredentialRejected(
                        "credential's obfuscation-secret presence ($credentialHasObfuscationSecret) disagrees with the trusted signed obfuscationMode (${trustedProfile.obfuscationMode})",
                    )
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
    /** B46-4A review fix (Finding 3/5) - no real, currently-trusted signed Hysteria2 profile exists for this endpoint; the network was never dialed. */
    data class NoTrustedBinding(val reason: String) : Hysteria2ProvisioningOutcome()
}
