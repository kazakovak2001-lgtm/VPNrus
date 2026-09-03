package net.pocvpn.client.controlplane

/**
 * B30 (task 9) - the closed, support-bundle-safe taxonomy for WHY one
 * control-plane origin attempt (activation, xray-profile, ingress-profile)
 * failed. Deliberately distinct from [net.pocvpn.client.provisioning.ProvisioningResult]/
 * [net.pocvpn.client.provisioning.IngressProfileResult] (this codebase's
 * existing, richer per-endpoint response types) the same way
 * [net.pocvpn.client.diagnostics.support.DiagnosticFailureReason] is
 * distinct from [net.pocvpn.client.diagnostics.VpnError] - a coarser,
 * closed vocabulary purpose-built for a non-technical tester's diagnostic
 * bundle, never a replacement for the richer type callers still branch on.
 * Never carries a low-level exception message/string - see
 * [ControlPlaneFailureClassifier].
 */
enum class ControlPlaneFailureReason {
    DNS_RESOLUTION_FAILED,
    CONNECT_TIMEOUT,
    TLS_TRUST_FAILED,
    HTTP_UNAVAILABLE,
    AUTHORIZATION_REJECTED,
    MALFORMED_RESPONSE,
    /** A response's own pinned/cross-checked facts (host/port/ingress kind/profile shape) disagreed with what was requested - e.g. [net.pocvpn.client.relay.IngressActivationOutcome.Mismatched]. Not a cryptographic signature check (this codebase's Ed25519 signature verification is [net.pocvpn.client.reachability.EndpointManifest]-specific, not part of activation/profile responses) - "trust rejection" here means the same fail-closed pinned-fact mismatch the Mismatched outcome already expresses, re-labeled into this taxonomy. */
    TRUST_VALIDATION_REJECTED,
    UNTRUSTED_REDIRECT_REJECTED,
    ALL_ORIGINS_EXHAUSTED,
}

/**
 * B30 - maps a raw [java.io.IOException] (never logged/inspected beyond its
 * runtime type - no message string ever crosses this boundary) into the
 * closed taxonomy above. `internal` so this classification is unit-testable
 * without opening a real socket.
 */
internal fun classifyControlPlaneIoException(e: Throwable): ControlPlaneFailureReason = when (e) {
    is java.net.UnknownHostException -> ControlPlaneFailureReason.DNS_RESOLUTION_FAILED
    is java.net.SocketTimeoutException -> ControlPlaneFailureReason.CONNECT_TIMEOUT
    is javax.net.ssl.SSLException -> ControlPlaneFailureReason.TLS_TRUST_FAILED
    else -> ControlPlaneFailureReason.HTTP_UNAVAILABLE
}
