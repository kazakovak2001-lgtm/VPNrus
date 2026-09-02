package net.pocvpn.client.provisioning

import net.pocvpn.client.reachability.IngressKind

/**
 * B26 (task D) - the outcome of one POST /v1/ingress-profile attempt.
 * Mirrors [XrayProfileResult]'s own shape/reasoning (a distinct wire shape
 * from the AWG/regular-gateway endpoints, so a single closed set covering
 * all three would force every caller to handle cases that can never occur
 * for the endpoint it actually called) plus the fields unique to an
 * ingress profile - [isRealityShaped] distinguishes a REALITY-transport
 * response (flow/realityPublicKey/shortId all present) from a TLS one
 * (all three null) without a caller having to re-derive that from
 * nullability alone.
 */
sealed class IngressProfileResult {

    data class Success(
        val ingressEndpointId: String,
        // B27 - the server's OWN claim of which IngressKind this ingress is
        // (parsed from the response's optional "ingress_kind" field -
        // absent means DIRECT_IP, the only kind every pre-B27 gateway ever
        // served). [net.pocvpn.client.relay.IngressProfileProvisioner.provision]
        // cross-checks this against the CALLER's own pinned expectation
        // before ever persisting anything - see that function's own docs.
        val ingressKind: IngressKind,
        val serverAddress: String,
        val serverPort: Int,
        val uuid: String,
        val serverName: String,
        val fingerprint: String,
        val flow: String?,
        val realityPublicKey: String?,
        val shortId: String?,
        val isRealityShaped: Boolean,
        val profileVersion: Int,
        val issuedAtEpochSeconds: Long,
        val expiresAtEpochSeconds: Long?,
        val probeUrl: String,
        val probeToken: String,
    ) : IngressProfileResult()

    /** HTTP 401 - unknown/invalid bearer/activation credential. */
    object Unauthorized : IngressProfileResult()

    /** HTTP 403 error=revoked - a once-valid activation credential was revoked. */
    object Revoked : IngressProfileResult()

    /** HTTP 403 error=expired - the activation credential's own validity window has passed. */
    object Expired : IngressProfileResult()

    /** HTTP 403 error=device_not_bound - the credential is valid but not bound to this device. */
    object DeviceNotBound : IngressProfileResult()

    /** HTTP 503 - the ingress role is not configured on this endpoint, or the ingress profile service is temporarily unavailable. */
    object ServiceUnavailable : IngressProfileResult()

    /** HTTP 200/201 but the body failed narrow structural validation - never used unparsed. */
    data class MalformedResponse(val reason: String) : IngressProfileResult()

    /** Anything else: connection failure, TLS failure, timeout, or an unexpected HTTP status. */
    data class NetworkError(val message: String) : IngressProfileResult()
}
