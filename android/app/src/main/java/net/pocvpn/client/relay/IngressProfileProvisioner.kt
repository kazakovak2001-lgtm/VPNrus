package net.pocvpn.client.relay

import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.provisioning.IngressProfileResult
import net.pocvpn.client.provisioning.ProvisioningClient
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind

/**
 * B26 (task D) - the real Android client control-plane path for a selected
 * ingress: POST /v1/ingress-profile -> validate the response actually names
 * the ingress THIS request targeted -> convert into [IngressClientProfile]
 * -> persist via [IngressProfileStore], endpoint-scoped by construction (see
 * that interface's own docs - a distinct file per [EndpointId], so this can
 * never overwrite a DIFFERENT ingress endpoint's profile).
 *
 * [ingressBinding] is the caller's own already-pinned fact (from the signed
 * manifest, via a real [net.pocvpn.client.smartconnect.AutoGatewaySelector.RelayAttemptCandidate]
 * or an explicit user-initiated "activate this ingress" action) - NEVER
 * re-derived from the HTTP response. [provision] additionally cross-checks
 * the response's own `server_address`/`server_port` against
 * [ingressBinding]'s host/port and fails closed with [IngressActivationOutcome.Mismatched]
 * on any disagreement (task D's own "fail closed on malformed response" /
 * task K's "malformed/mismatched profile is rejected") - a compromised or
 * misconfigured control-plane cannot silently redirect this device's saved
 * credential to a different host than the one it was pinned against.
 */
class IngressProfileProvisioner(
    private val store: IngressProfileStore,
    // Additive seam, same reasoning as XrayProfileProvisioner's own
    // fetchXrayProfile param: defaults to the real network call.
    private val fetchIngressProfile: (publicKey: String, activationCredential: String, endpointHost: String, useTls: Boolean) -> IngressProfileResult =
        ProvisioningClient::fetchIngressProfile,
    private val nowProvider: () -> Long = System::currentTimeMillis,
) {
    suspend fun provision(
        ingressEndpointId: EndpointId,
        ingressBinding: EndpointTransportBinding,
        ingressTransport: TransportKind,
        publicKey: String,
        activationCredential: String,
    ): IngressActivationOutcome {
        val useTls = when (ingressTransport) {
            TransportKind.TLS_TCP -> true
            TransportKind.XRAY_REALITY -> false
            else -> return IngressActivationOutcome.UnsupportedTransport
        }

        val result = fetchIngressProfile(publicKey, activationCredential, ingressBinding.host, useTls)
        return when (result) {
            is IngressProfileResult.Success -> {
                if (result.ingressEndpointId != ingressEndpointId.value) {
                    return IngressActivationOutcome.Mismatched(
                        "response named ingress '${result.ingressEndpointId}', expected '${ingressEndpointId.value}'",
                    )
                }
                if (result.serverAddress != ingressBinding.host || result.serverPort != ingressBinding.port) {
                    return IngressActivationOutcome.Mismatched(
                        "response server ${result.serverAddress}:${result.serverPort} does not match the pinned binding ${ingressBinding.host}:${ingressBinding.port}",
                    )
                }
                if (useTls && result.isRealityShaped) {
                    return IngressActivationOutcome.Mismatched("requested TLS but response carries REALITY-shaped fields")
                }
                if (!useTls && !result.isRealityShaped) {
                    return IngressActivationOutcome.Mismatched("requested REALITY but response carries no REALITY fields")
                }

                val profile = IngressClientProfile(
                    ingressEndpointId = ingressEndpointId,
                    ingressBinding = ingressBinding,
                    transport = ingressTransport,
                    realityProfile = if (!useTls) {
                        XrayProfile(
                            server = result.serverAddress,
                            serverPort = result.serverPort,
                            uuid = result.uuid,
                            flow = result.flow.orEmpty(),
                            serverName = result.serverName,
                            fingerprint = result.fingerprint,
                            realityPublicKey = result.realityPublicKey.orEmpty(),
                            shortId = result.shortId.orEmpty(),
                        )
                    } else {
                        null
                    },
                    tlsProfile = if (useTls) {
                        XrayTlsProfile(
                            server = result.serverAddress,
                            serverPort = result.serverPort,
                            uuid = result.uuid,
                            serverName = result.serverName,
                            fingerprint = result.fingerprint,
                        )
                    } else {
                        null
                    },
                    profileVersion = result.profileVersion,
                    issuedAtEpochMillis = result.issuedAtEpochSeconds * 1000L,
                    expiresAtEpochMillis = result.expiresAtEpochSeconds?.let { it * 1000L },
                    endToEndProbeUrl = result.probeUrl,
                    endToEndProbeToken = result.probeToken,
                )
                store.saveProfile(profile)
                IngressActivationOutcome.Saved(profile)
            }
            is IngressProfileResult.Unauthorized -> IngressActivationOutcome.AuthorizationFailed
            is IngressProfileResult.Revoked -> IngressActivationOutcome.AuthorizationFailed
            is IngressProfileResult.Expired -> IngressActivationOutcome.AuthorizationFailed
            is IngressProfileResult.DeviceNotBound -> IngressActivationOutcome.AuthorizationFailed
            is IngressProfileResult.ServiceUnavailable -> IngressActivationOutcome.Unavailable
            is IngressProfileResult.MalformedResponse -> IngressActivationOutcome.Mismatched(result.reason)
            is IngressProfileResult.NetworkError -> IngressActivationOutcome.Unavailable
        }
    }

    /**
     * B26 (task E) - the smallest safe refresh policy: reuse a still-valid
     * stored profile as-is; re-activate ONLY when nothing usable is stored
     * (not provisioned, mismatched, or expired). Bounded by construction -
     * this performs at most ONE network attempt per call, never a retry
     * loop; the caller ([net.pocvpn.client.MainViewModel]'s relay attempt
     * path) decides whether/when to call this again, exactly like every
     * other bounded attempt in the combined Auto sequence.
     */
    suspend fun ensureFreshProfile(
        ingressEndpointId: EndpointId,
        ingressBinding: EndpointTransportBinding,
        ingressTransport: TransportKind,
        publicKey: String,
        activationCredential: String,
    ): IngressActivationOutcome {
        val existing = store.getProfileOrNull(ingressEndpointId)
        val stillGood = existing != null &&
            existing.ingressEndpointId == ingressEndpointId &&
            existing.ingressBinding == ingressBinding &&
            existing.transport == ingressTransport &&
            !existing.isExpired(nowProvider())
        if (stillGood) {
            return IngressActivationOutcome.Saved(existing!!)
        }
        return provision(ingressEndpointId, ingressBinding, ingressTransport, publicKey, activationCredential)
    }
}

/** B26 (task D) - the typed result of one [IngressProfileProvisioner.provision] attempt. */
sealed class IngressActivationOutcome {
    data class Saved(val profile: IngressClientProfile) : IngressActivationOutcome()
    object AuthorizationFailed : IngressActivationOutcome()
    object Unavailable : IngressActivationOutcome()
    object UnsupportedTransport : IngressActivationOutcome()
    data class Mismatched(val reason: String) : IngressActivationOutcome()
}
