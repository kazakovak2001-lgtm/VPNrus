package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode

/**
 * B29 (task D) - THE ONE place a real [DiagnosticSession] is assembled,
 * automatically, from the SAME data the real connect flow already computes
 * (task's own "reuse real existing state/events... do not create a second
 * connection state machine merely for diagnostics"). Every `record*`
 * function here is narrow and typed - none accepts a raw string, so nothing
 * secret-shaped can enter [DiagnosticEvent.tags] through this API at all
 * (the structural half of the sanitization boundary - see
 * [DiagnosticSanitizer]'s own docs for the second, defense-in-depth half).
 *
 * [net.pocvpn.client.MainViewModel] owns exactly one instance of this
 * (constructed once, alongside its other collaborators) and calls it from
 * real call sites - never a parallel/independent tracker.
 */
class SupportDiagnosticsRecorder(
    private val store: DiagnosticSessionStore,
    private val appVersionName: String,
    private val appVersionCode: Long,
    private val nowProvider: () -> Long = System::currentTimeMillis,
    // A locally-generated, opaque GROUPING id - never a device/tunnel
    // identity, never sent anywhere unless the user explicitly exports/
    // shares this bundle (task J). Safe to display verbatim in the UI
    // ("Copy diagnostic ID") - it identifies this ONE incident record, not
    // this device or this user.
    private val sessionIdProvider: () -> String = { java.util.UUID.randomUUID().toString() },
) {
    /**
     * B29 (task G) - every field here MUST be read together, from the SAME
     * actual decision/execution snapshot the real connect attempt used
     * (reusing B28's own `CombinedAutoRankingSnapshot` discipline) - never
     * independently recomputed afterward. The caller ([net.pocvpn.client
     * .MainViewModel]) is responsible for building this from one read;
     * [SupportDiagnosticsRecorder] itself never calls back into
     * [net.pocvpn.client.MainViewModel] to re-derive any of it.
     */
    data class StartContext(
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
    )

    private class OpenSession(
        val sessionId: String,
        val startedAtEpochMillis: Long,
        val context: StartContext,
    ) {
        var selectedPathKind: PathKind = PathKind.NONE
        var selectedTransportKind: TransportKind? = null
        val events = mutableListOf<DiagnosticEvent>()
    }

    private var open: OpenSession? = null

    /** Currently-open session id, or null - lets a caller correlate a live UI state with the session being built, without reading store internals. */
    fun currentSessionId(): String? = open?.sessionId

    /**
     * Starts a NEW session, ending (as [DiagnosticOutcome.IN_PROGRESS] never
     * persisted - see [abandonOpenSession]) whatever was previously open.
     * Records the three evidence-observation events every session always
     * opens with (task B's own first three event categories).
     */
    fun startSession(context: StartContext) {
        abandonOpenSession()
        open = OpenSession(sessionIdProvider(), nowProvider(), context)
        record(DiagnosticEventType.NETWORK_PROFILE_OBSERVED)
        record(DiagnosticEventType.RESTRICTION_CLASSIFIED, mapOf(TAG_RESTRICTION_CLASS to context.rawRestrictionClass.name))
        record(DiagnosticEventType.RESTRICTION_STABILIZED, mapOf(TAG_RESTRICTION_CLASS to context.stabilizedRestrictionClass.name))
    }

    /** A session was left open with no terminal outcome (e.g. superseded by a new attempt before finishing) - silently dropped, never persisted half-built and never crashes the caller. */
    private fun abandonOpenSession() {
        open = null
    }

    fun recordManifestSourceSelected(sourceLabel: String) =
        record(DiagnosticEventType.MANIFEST_SOURCE_SELECTED, mapOf(TAG_SOURCE to sourceLabel))

    fun recordCandidateRanked(candidateCount: Int) =
        record(DiagnosticEventType.CANDIDATE_RANKED, mapOf(TAG_COUNT to candidateCount.toString()))

    /** Also pins [pathKind]/[transportKind] as the session's own selected-path fields (task A) - the LAST attempt started wins, matching which attempt a session's terminal outcome actually describes. */
    fun recordCandidateAttemptStarted(pathKind: PathKind, transportKind: TransportKind) {
        open?.selectedPathKind = pathKind
        open?.selectedTransportKind = transportKind
        record(DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED, mapOf(TAG_PATH_KIND to pathKind.name, TAG_TRANSPORT_KIND to transportKind.name))
    }

    fun recordEndpointReachabilityResult(state: ReachabilityState) =
        record(DiagnosticEventType.ENDPOINT_REACHABILITY_RESULT, mapOf(TAG_STATE to state.name))

    fun recordTransportStart(transportKind: TransportKind) =
        record(DiagnosticEventType.TRANSPORT_START, mapOf(TAG_TRANSPORT_KIND to transportKind.name))

    fun recordTransportHandshakeResult(success: Boolean) =
        record(DiagnosticEventType.TRANSPORT_HANDSHAKE_RESULT, mapOf(TAG_SUCCESS to success.toString()))

    fun recordDataPlaneReadinessResult(stage: RelayReadinessStage) =
        record(DiagnosticEventType.DATA_PLANE_READINESS_RESULT, mapOf(TAG_STAGE to stage.name))

    fun recordRelayActivationRequired() = record(DiagnosticEventType.RELAY_ACTIVATION_REQUIRED)

    fun recordRelayActivationResult(outcome: IngressActivationOutcome) {
        val reason = mapIngressActivationOutcomeToFailureReason(outcome)
        record(
            DiagnosticEventType.RELAY_ACTIVATION_RESULT,
            buildMap {
                put(TAG_SUCCESS, (reason == null).toString())
                reason?.let { put(TAG_FAILURE_REASON, it.name) }
            },
        )
    }

    fun recordRelayEndToEndProofResult(success: Boolean, category: RelayFailureCategory?) {
        record(
            DiagnosticEventType.RELAY_END_TO_END_PROOF_RESULT,
            buildMap {
                put(TAG_SUCCESS, success.toString())
                category?.let { put(TAG_FAILURE_REASON, mapRelayFailureCategoryToFailureReason(it).name) }
            },
        )
    }

    /**
     * NON-TERMINAL - records [DiagnosticEventType.PATH_FAILED] for ONE
     * candidate/attempt within a possibly still-continuing bounded failover
     * sequence (e.g. Auto's own combined Direct/Relayed retries - see
     * [net.pocvpn.client.MainViewModel.attemptCombined]'s own docs). Does
     * NOT finish the session - a multi-candidate connect() request is still
     * ONE session, ONE timeline, until something genuinely terminal happens
     * (see [finishFailed]/[finishProtected]/[finishDisconnected]).
     */
    fun recordPathFailed(reason: DiagnosticFailureReason) =
        record(DiagnosticEventType.PATH_FAILED, mapOf(TAG_FAILURE_REASON to reason.name))

    /** NON-TERMINAL - see [recordPathFailed]'s own docs; a control-plane exchange (e.g. one relay activation network call) failed, but the combined sequence may still continue with a different candidate. */
    fun recordControlPlaneFailure(reason: DiagnosticFailureReason) =
        record(DiagnosticEventType.CONTROL_PLANE_FAILURE, mapOf(TAG_FAILURE_REASON to reason.name))

    /** TERMINAL - the whole connect() request is now genuinely exhausted: restriction evidence suspected a fixed allowlist and no eligible relay existed at all (checked before any candidate attempt even starts - see [net.pocvpn.client.MainViewModel.connectAuto]'s own docs). */
    fun finishRestrictedNetworkExhaustion() {
        record(DiagnosticEventType.RESTRICTED_NETWORK_EXHAUSTION)
        finish(DiagnosticOutcome.FAILED, DiagnosticFailureReason.RESTRICTED_NETWORK_NO_VIABLE_RELAY)
    }

    /** TERMINAL - the whole connect() request ends in failure, for [reason] - see [recordPathFailed]'s own docs for the non-terminal, per-candidate counterpart. */
    fun finishFailed(reason: DiagnosticFailureReason) = finish(DiagnosticOutcome.FAILED, reason)

    /** TERMINAL - records [DiagnosticEventType.VPN_PROTECTED] (also, redundantly per requirement B's own vocabulary, [DiagnosticEventType.PATH_SUCCEEDED]) and finishes the session as [DiagnosticOutcome.PROTECTED]. */
    fun finishProtected() {
        record(DiagnosticEventType.PATH_SUCCEEDED)
        record(DiagnosticEventType.VPN_PROTECTED)
        finish(DiagnosticOutcome.PROTECTED, null)
    }

    /** TERMINAL - no-op if no session is open (an ordinary disconnect after a session already finished, or before one ever started - never a spurious empty session). */
    fun finishDisconnected() {
        if (open == null) return
        record(DiagnosticEventType.VPN_DISCONNECTED)
        finish(DiagnosticOutcome.DISCONNECTED, null)
    }

    private fun record(type: DiagnosticEventType, tags: Map<String, String> = emptyMap()) {
        val session = open ?: return
        // Task D's own per-session bound (see DiagnosticSession.MAX_EVENTS_PER_SESSION) - a runaway retry loop can never grow one session's timeline unboundedly.
        if (session.events.size >= DiagnosticSession.MAX_EVENTS_PER_SESSION) return
        session.events.add(DiagnosticEvent(type, nowProvider(), tags))
    }

    private fun finish(outcome: DiagnosticOutcome, failureReason: DiagnosticFailureReason?) {
        val session = open ?: return
        store.append(
            DiagnosticSession(
                sessionId = session.sessionId,
                startedAtEpochMillis = session.startedAtEpochMillis,
                endedAtEpochMillis = nowProvider(),
                appVersionName = appVersionName,
                appVersionCode = appVersionCode,
                networkType = session.context.networkType,
                networkValidatedInternet = session.context.networkValidatedInternet,
                networkCaptivePortal = session.context.networkCaptivePortal,
                networkIpv4Available = session.context.networkIpv4Available,
                networkIpv6Available = session.context.networkIpv6Available,
                networkFingerprintId = session.context.networkFingerprintId,
                rawRestrictionClass = session.context.rawRestrictionClass,
                stabilizedRestrictionClass = session.context.stabilizedRestrictionClass,
                routingMode = session.context.routingMode,
                gatewaySelectionMode = session.context.gatewaySelectionMode,
                selectedPathKind = session.selectedPathKind,
                selectedTransportKind = session.selectedTransportKind,
                events = session.events.toList(),
                outcome = outcome,
                failureReason = failureReason,
            ),
        )
        open = null
    }

    private companion object {
        const val TAG_RESTRICTION_CLASS = "restrictionClass"
        const val TAG_SOURCE = "source"
        const val TAG_COUNT = "count"
        const val TAG_PATH_KIND = "pathKind"
        const val TAG_TRANSPORT_KIND = "transportKind"
        const val TAG_STATE = "state"
        const val TAG_SUCCESS = "success"
        const val TAG_STAGE = "stage"
        const val TAG_FAILURE_REASON = "failureReason"
    }
}
