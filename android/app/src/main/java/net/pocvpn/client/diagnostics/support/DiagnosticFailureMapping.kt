package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.reachability.ManifestSource
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayProbeFailureKind
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind

/**
 * B29 (task C) - pure mapping from every real, existing outcome type this
 * codebase already produces into the closed [DiagnosticFailureReason]
 * vocabulary a support bundle carries. Deliberately NEVER replaces
 * [VpnError]/[RelayFailureCategory]/[IngressActivationOutcome] - those stay
 * the real, authoritative outcome types everywhere else in this codebase;
 * this file only RE-LABELS them for one consumer (the support bundle).
 */
fun mapVpnErrorToFailureReason(error: VpnError): DiagnosticFailureReason = when (error) {
    VpnError.PermissionDenied -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.GatewayConfigurationMissing -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.InvalidGatewayConfiguration -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.BackendStartFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    is VpnError.BackendStopFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.NetworkUnavailable -> DiagnosticFailureReason.NETWORK_UNAVAILABLE
    VpnError.ReconnectExhausted -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    is VpnError.ConfigurationMappingFailure -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.AlreadyInProgress -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.HandshakeTimeout -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    VpnError.SplitTunnelingNoAppsSelected -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.NoCandidateAvailable -> DiagnosticFailureReason.NO_CANDIDATE
    is VpnError.UnsupportedTransportSelected -> DiagnosticFailureReason.INTERNAL_ERROR
    VpnError.RestrictedNetworkNoViableRelay -> DiagnosticFailureReason.RESTRICTED_NETWORK_NO_VIABLE_RELAY
}

fun mapRelayFailureCategoryToFailureReason(category: RelayFailureCategory): DiagnosticFailureReason = when (category) {
    RelayFailureCategory.INGRESS_UNREACHABLE -> DiagnosticFailureReason.INGRESS_UNREACHABLE
    RelayFailureCategory.INGRESS_HANDSHAKE_FAILED -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    RelayFailureCategory.UPSTREAM_EXIT_HANDSHAKE_FAILED -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RelayFailureCategory.RELAY_AUTH_FAILED -> DiagnosticFailureReason.ACTIVATION_FAILED
    RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED -> DiagnosticFailureReason.RELAY_END_TO_END_PROOF_FAILED
    RelayFailureCategory.PROFILE_NOT_PROVISIONED -> DiagnosticFailureReason.INGRESS_PROFILE_REQUIRED
    RelayFailureCategory.PROFILE_MISMATCH -> DiagnosticFailureReason.INGRESS_PROFILE_MISMATCH
    RelayFailureCategory.PROFILE_EXPIRED -> DiagnosticFailureReason.INGRESS_PROFILE_REQUIRED
    RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED -> DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE
}

/** A failed ingress handshake does not reveal which CDN/origin hop failed. */
fun mapRelayFailureForPath(
    category: RelayFailureCategory,
    pathKind: PathKind,
    transportKind: TransportKind?,
): DiagnosticFailureReason =
    if (pathKind == PathKind.CHAIN_CDN && transportKind == TransportKind.XRAY_XHTTP) {
        when (category) {
            RelayFailureCategory.INGRESS_HANDSHAKE_FAILED -> DiagnosticFailureReason.XHTTP_HANDSHAKE_FAILURE
            // This category comes from HttpRelayEndToEndProbe's out-of-band
            // control-plane check; it is not an in-tunnel data-plane proof.
            RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED -> DiagnosticFailureReason.RELAY_PROOF_FAILURE
            else -> mapRelayFailureCategoryToFailureReason(category)
        }
    } else {
        mapRelayFailureCategoryToFailureReason(category)
    }

/** A probe's typed IOException subtype is about its own HTTPS request, never the CDN/Xray hop. */
fun mapRelayProbeFailureForPath(
    category: RelayFailureCategory,
    failureKind: RelayProbeFailureKind?,
    pathKind: PathKind,
    transportKind: TransportKind?,
): DiagnosticFailureReason =
    if ((pathKind == PathKind.CHAIN_CDN || pathKind == PathKind.CHAIN_DIRECT) && transportKind != null &&
        category == RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE
    ) {
        when (failureKind) {
            RelayProbeFailureKind.DNS_RESOLUTION_FAILED -> DiagnosticFailureReason.RELAY_PROBE_DNS_FAILURE
            RelayProbeFailureKind.TLS_HANDSHAKE_FAILED -> DiagnosticFailureReason.RELAY_PROBE_TLS_FAILURE
            RelayProbeFailureKind.REQUEST_TIMED_OUT -> DiagnosticFailureReason.RELAY_PROBE_TIMEOUT
            null -> mapRelayFailureForPath(category, pathKind, transportKind)
        }
    } else mapRelayFailureForPath(category, pathKind, transportKind)

/** Xray's native, in-tunnel remote confirmation failed after local core start. */
fun mapTransportFailureForPath(
    failure: TransportFailureKind?,
    pathKind: PathKind,
    transportKind: TransportKind?,
): DiagnosticFailureReason? =
    if ((failure == TransportFailureKind.REMOTE_UNCONFIRMED || failure == TransportFailureKind.RELAY_DATA_PLANE_LOST) &&
        pathKind == PathKind.CHAIN_CDN && transportKind == TransportKind.XRAY_XHTTP
    ) DiagnosticFailureReason.DATA_PLANE_PROOF_FAILURE else null

/** Returns null for [IngressActivationOutcome.Saved] (not a failure). */
fun mapIngressActivationOutcomeToFailureReason(outcome: IngressActivationOutcome): DiagnosticFailureReason? = when (outcome) {
    is IngressActivationOutcome.Saved -> null
    IngressActivationOutcome.AuthorizationFailed -> DiagnosticFailureReason.ACTIVATION_FAILED
    IngressActivationOutcome.Unavailable -> DiagnosticFailureReason.CONTROL_PLANE_UNREACHABLE
    IngressActivationOutcome.UnsupportedTransport -> DiagnosticFailureReason.ACTIVATION_FAILED
    is IngressActivationOutcome.Mismatched -> DiagnosticFailureReason.INGRESS_PROFILE_MISMATCH
}

/**
 * B29 - the ONE place [RestrictionClass.POSSIBLE_HARD_WHITELIST] itself
 * (not merely "no viable relay" - see [mapVpnErrorToFailureReason]'s
 * [VpnError.RestrictedNetworkNoViableRelay] case for that narrower one)
 * becomes a support-bundle-facing failure reason, for a session that never
 * even reached the point of building combined attempts (e.g. NO_NETWORK/
 * CAPTIVE_PORTAL take priority - see [net.pocvpn.client.smartconnect
 * .RestrictionClassifier]'s own priority order, checked here in the SAME
 * order for consistency). Returns null for every class that is not itself
 * failure-worthy on its own.
 */
fun mapRestrictionClassToFailureReason(restrictionClass: RestrictionClass): DiagnosticFailureReason? = when (restrictionClass) {
    RestrictionClass.NO_NETWORK -> DiagnosticFailureReason.NETWORK_UNAVAILABLE
    RestrictionClass.CAPTIVE_PORTAL -> DiagnosticFailureReason.CAPTIVE_PORTAL
    RestrictionClass.GATEWAY_HTTPS_UNREACHABLE -> DiagnosticFailureReason.GATEWAY_UNREACHABLE
    RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING -> DiagnosticFailureReason.PROTOCOL_OR_TRANSPORT_BLOCKED
    RestrictionClass.POSSIBLE_HARD_WHITELIST -> DiagnosticFailureReason.POSSIBLE_HARD_WHITELIST
    RestrictionClass.POSSIBLE_EARLY_DROP -> DiagnosticFailureReason.POSSIBLE_EARLY_DROP
    RestrictionClass.POSSIBLE_FULL_SHUTDOWN -> DiagnosticFailureReason.POSSIBLE_FULL_SHUTDOWN
    RestrictionClass.INTERNET_NOT_VALIDATED,
    RestrictionClass.NETWORK_RECOVERING,
    RestrictionClass.NO_RESTRICTION_OBSERVED,
    RestrictionClass.UNKNOWN,
    -> null
}

/**
 * PR #43 review fix - pure mapping from the real, existing
 * [net.pocvpn.client.reachability.ManifestSource]? (null meaning "no trusted
 * manifest") into the closed [ManifestSourceKind] vocabulary
 * [SupportDiagnosticsRecorder.recordManifestSourceSelected] records. Never
 * invents a new source; only re-labels the two real
 * [net.pocvpn.client.reachability.EndpointManifestRepository] outcomes.
 */
fun mapManifestSourceToManifestSourceKind(source: ManifestSource?): ManifestSourceKind = when (source) {
    ManifestSource.LAST_KNOWN_GOOD -> ManifestSourceKind.LAST_KNOWN_GOOD
    ManifestSource.EMBEDDED_BOOTSTRAP -> ManifestSourceKind.EMBEDDED_BOOTSTRAP
    // B56-2/PR #93 review fix - EndpointManifestRepository.trustedState()/
    // trustedSource() (the only real callers this mapper serves) never
    // return IMPORTED_SIGNED_BOOTSTRAP: it is delivery provenance reported
    // once at import time by SignedBootstrapBundleImporter.import()'s own
    // Accepted.source, never a trustedState() outcome - so this branch is
    // unreachable via THIS mapper's current call sites. It maps to the
    // matching ManifestSourceKind.IMPORTED_SIGNED_BOOTSTRAP truthfully
    // (never collapsed into NONE, which would falsely claim "no known
    // source") so that if a future caller ever hands this mapper an
    // import-time provenance value, the diagnostic stays accurate instead
    // of erasing a real, known source - see
    // ManifestSource.IMPORTED_SIGNED_BOOTSTRAP's own docs.
    ManifestSource.IMPORTED_SIGNED_BOOTSTRAP -> ManifestSourceKind.IMPORTED_SIGNED_BOOTSTRAP
    null -> ManifestSourceKind.NONE
}

/**
 * B30 (task 9) - pure mapping from [ControlPlaneFailureReason] (the closed
 * taxonomy net.pocvpn.client.controlplane.TrustedOriginRequestExecutor and
 * its callers classify a control-plane attempt failure into) onto this
 * file's own [DiagnosticFailureReason] vocabulary, exactly the same
 * "re-label, never replace" discipline every other mapper in this file
 * follows.
 */
fun mapControlPlaneFailureReasonToFailureReason(reason: ControlPlaneFailureReason): DiagnosticFailureReason = when (reason) {
    ControlPlaneFailureReason.DNS_RESOLUTION_FAILED -> DiagnosticFailureReason.CONTROL_PLANE_DNS_FAILURE
    ControlPlaneFailureReason.CONNECT_TIMEOUT -> DiagnosticFailureReason.CONTROL_PLANE_CONNECT_TIMEOUT
    ControlPlaneFailureReason.TLS_TRUST_FAILED -> DiagnosticFailureReason.CONTROL_PLANE_TLS_FAILURE
    ControlPlaneFailureReason.HTTP_UNAVAILABLE -> DiagnosticFailureReason.CONTROL_PLANE_HTTP_UNAVAILABLE
    ControlPlaneFailureReason.AUTHORIZATION_REJECTED -> DiagnosticFailureReason.CONTROL_PLANE_AUTHORIZATION_REJECTED
    ControlPlaneFailureReason.MALFORMED_RESPONSE -> DiagnosticFailureReason.CONTROL_PLANE_MALFORMED_RESPONSE
    ControlPlaneFailureReason.TRUST_VALIDATION_REJECTED -> DiagnosticFailureReason.CONTROL_PLANE_TRUST_REJECTED
    ControlPlaneFailureReason.UNTRUSTED_REDIRECT_REJECTED -> DiagnosticFailureReason.CONTROL_PLANE_REDIRECT_REJECTED
    ControlPlaneFailureReason.ALL_ORIGINS_EXHAUSTED -> DiagnosticFailureReason.CONTROL_PLANE_ORIGINS_EXHAUSTED
}
