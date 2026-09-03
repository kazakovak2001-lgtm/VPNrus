package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * B29 - the real, "which shape of path was selected" label a support bundle
 * needs to explain a decision - deliberately the SAME three labels
 * [net.pocvpn.client.MainViewModel.combinedAutoRankingDiagnostics] already
 * uses (`"DIRECT"`/`"CHAIN_DIRECT"`/`"CHAIN_CDN"`, derived the SAME way -
 * off [net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt
 * .RelayedAttempt.candidate.ingressKind] - never a second labeling scheme),
 * plus [PRIVATE] for B22's own third gateway-selection authority and [NONE]
 * for a session that never reached a selected path at all (e.g. exhausted
 * before any candidate was chosen).
 */
enum class PathKind { DIRECT, CHAIN_DIRECT, CHAIN_CDN, PRIVATE, NONE }

/**
 * PR #43 review fix - the closed, non-secret label for which trusted-manifest
 * source [net.pocvpn.client.MainViewModel.connectAuto] read from, mirroring
 * [net.pocvpn.client.reachability.ManifestSource]'s own two real values
 * (never a provider/host/URL-shaped label) plus [NONE] for "no trusted
 * manifest at all" (the same case the old, since-removed raw-string call site
 * expressed as the free-text `"none"`). See
 * [mapManifestSourceToManifestSourceKind] for the pure mapping from the real
 * [net.pocvpn.client.reachability.ManifestSource]? into this vocabulary.
 */
enum class ManifestSourceKind { LAST_KNOWN_GOOD, EMBEDDED_BOOTSTRAP, NONE }

/**
 * B29 (task B) - the bounded, typed timeline vocabulary a support bundle
 * records. Every value here names a REAL transition this codebase's own
 * existing state (network profile, [RestrictionClassifier]/[RestrictionStabilizer],
 * [net.pocvpn.client.smartconnect.AutoGatewaySelector], [net.pocvpn.client
 * .vpn.VpnSessionHealth], [net.pocvpn.client.relay.RelayReadinessStage],
 * [net.pocvpn.client.relay.IngressActivationOutcome]) already produces - this
 * enum is a LABELING vocabulary over that existing state, never a second,
 * independently-driven state machine (task's own "reuse real existing
 * state/events where possible").
 */
enum class DiagnosticEventType {
    NETWORK_PROFILE_OBSERVED,
    RESTRICTION_CLASSIFIED,
    RESTRICTION_STABILIZED,
    MANIFEST_SOURCE_SELECTED,
    CANDIDATE_RANKED,
    CANDIDATE_ATTEMPT_STARTED,
    ENDPOINT_REACHABILITY_RESULT,
    TRANSPORT_START,
    TRANSPORT_HANDSHAKE_RESULT,
    DATA_PLANE_READINESS_RESULT,
    RELAY_ACTIVATION_REQUIRED,
    RELAY_ACTIVATION_RESULT,
    RELAY_END_TO_END_PROOF_RESULT,
    PATH_FAILED,
    PATH_SUCCEEDED,
    RESTRICTED_NETWORK_EXHAUSTION,
    CONTROL_PLANE_FAILURE,
    VPN_PROTECTED,
    VPN_DISCONNECTED,
}

/**
 * B29 (task C) - the typed failure taxonomy a support bundle reports,
 * DISTINCT from (and mapped FROM, never replacing - see
 * [net.pocvpn.client.diagnostics.support.mapVpnErrorToFailureReason]/
 * [mapRelayFailureCategoryToFailureReason]/[mapIngressActivationOutcomeToFailureReason])
 * every existing [net.pocvpn.client.diagnostics.VpnError]/
 * [net.pocvpn.client.relay.RelayFailureCategory]/
 * [net.pocvpn.client.relay.IngressActivationOutcome]. Exists because none of
 * those three existing types alone can express "why did THIS support
 * incident happen" across Direct, relay, and control-plane causes in one
 * closed vocabulary a non-technical tester's bundle can carry.
 */
enum class DiagnosticFailureReason {
    NETWORK_UNAVAILABLE,
    CAPTIVE_PORTAL,
    DNS_FAILURE,
    GATEWAY_UNREACHABLE,
    PROTOCOL_OR_TRANSPORT_BLOCKED,
    DATA_PLANE_NOT_READY,
    POSSIBLE_HARD_WHITELIST,
    RESTRICTED_NETWORK_NO_VIABLE_RELAY,
    INGRESS_UNREACHABLE,
    INGRESS_PROFILE_REQUIRED,
    INGRESS_PROFILE_MISMATCH,
    RELAY_END_TO_END_PROOF_FAILED,
    ACTIVATION_FAILED,
    CONTROL_PLANE_UNREACHABLE,
    MANIFEST_UNAVAILABLE,
    NO_CANDIDATE,
    INTERNAL_ERROR,
}

/** B29 - the terminal shape of one [DiagnosticSession], mirroring [net.pocvpn.client.vpn.VpnSessionHealth]'s own real terminal states (never a fourth, independently-invented state). */
enum class DiagnosticOutcome { IN_PROGRESS, PROTECTED, FAILED, DISCONNECTED }

/**
 * B29 (task B) - one bounded timeline entry. [tags] is a CLOSED, already-
 * sanitized key/value set - every value here MUST already be one of an
 * enum name, a small integer/boolean rendered as text, or an opaque id
 * (e.g. [net.pocvpn.client.reachability.NetworkFingerprinter]'s own output)
 * - see [DiagnosticSanitizer] for the defense-in-depth check applied again
 * at export time. NEVER a free-text message, host, credential, or key -
 * [SupportDiagnosticsRecorder]'s own typed `record*` functions are the ONLY
 * production call sites that construct this, and none of them accept a raw
 * string parameter.
 */
data class DiagnosticEvent(
    val type: DiagnosticEventType,
    val atEpochMillis: Long,
    val tags: Map<String, String> = emptyMap(),
)

/**
 * B29 (task A) - one connection/support incident's sanitized, structured
 * evidence. Deliberately carries NO endpoint host/IP (task's own "do not
 * expose actual endpoint host/IP unless explicitly proven necessary" - not
 * proven necessary here) - only stable logical ids ([PathKind]/[TransportKind]
 * enum names) and the coarse, already-privacy-reviewed
 * [networkFingerprintId] ([net.pocvpn.client.reachability.NetworkFingerprinter]'s
 * own output, or null when no fingerprint key was ever wired).
 *
 * [rawRestrictionClass]/[stabilizedRestrictionClass] and [selectedPathKind]/
 * [selectedTransportKind] MUST all come from the SAME actual decision/
 * execution read (task requirement G, reusing B28's own snapshot
 * discipline) - see [SupportDiagnosticsRecorder.startSession]'s own docs for
 * how this is enforced: they are captured together, once, from one
 * [net.pocvpn.client.MainViewModel] snapshot read, never independently
 * recomputed afterward.
 */
data class DiagnosticSession(
    val sessionId: String,
    val startedAtEpochMillis: Long,
    val endedAtEpochMillis: Long?,
    val appVersionName: String,
    val appVersionCode: Long,
    val networkType: NetworkType,
    val networkValidatedInternet: Boolean,
    val networkCaptivePortal: Boolean,
    val networkIpv4Available: Boolean,
    val networkIpv6Available: Boolean,
    val networkFingerprintId: String?,
    val rawRestrictionClass: RestrictionClass,
    val stabilizedRestrictionClass: RestrictionClass,
    val routingMode: RoutingMode,
    val gatewaySelectionMode: GatewaySelectionMode,
    val selectedPathKind: PathKind,
    val selectedTransportKind: TransportKind?,
    val events: List<DiagnosticEvent>,
    val outcome: DiagnosticOutcome,
    val failureReason: DiagnosticFailureReason?,
) {
    init {
        // B29 (task D) - a per-session bound, independent of the store's own
        // cross-session retention bound below: no single incident, however
        // long-running, may grow this timeline unboundedly.
        require(events.size <= MAX_EVENTS_PER_SESSION) {
            "DiagnosticSession events must never exceed $MAX_EVENTS_PER_SESSION (task D's own bounded-capture requirement)"
        }
    }

    companion object {
        const val MAX_EVENTS_PER_SESSION = 200
    }
}
