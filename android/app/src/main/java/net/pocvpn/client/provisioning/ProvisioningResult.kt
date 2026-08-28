package net.pocvpn.client.provisioning

/**
 * B8B3A - the outcome of one POST /v1/peers attempt against the live
 * production edge. Deliberately a closed set the caller must exhaustively
 * handle - there is no generic "failure" case, so a UI can always show a
 * specific state (provisioning / success / unauthorized / network-or-TLS
 * error) rather than a catch-all.
 */
sealed class ProvisioningResult {

    data class Success(
        val clientTunnelIp: String,
        val gatewayPublicKey: String,
        val gatewayTunnelIp: String,
        val endpointHost: String,
        val endpointPort: Int,
    ) : ProvisioningResult()

    /** HTTP 401 - unknown or revoked bearer token. */
    object Unauthorized : ProvisioningResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : ProvisioningResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : ProvisioningResult()
}
