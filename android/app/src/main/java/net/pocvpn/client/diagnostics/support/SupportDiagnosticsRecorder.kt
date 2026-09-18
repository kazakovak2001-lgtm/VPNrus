package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.controlplane.ControlPlaneFailureReason
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.ReachabilityState
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayProbeFailureKind
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode

/** Pinned route identity; relay ingress/exit are planned until their respective execution boundaries are observed. */
sealed interface AttemptEndpointIdentity {
    data class Direct(val endpointId: EndpointId) : AttemptEndpointIdentity
    data class Relayed(val ingressEndpointId: EndpointId, val exitEndpointId: EndpointId) : AttemptEndpointIdentity
}

/**
 * B29 (task D) - THE ONE place a real [DiagnosticSession] is assembled,
 * automatically, from the SAME data the real connect flow already computes
 * (task's own "reuse real existing state/events... do not create a second
 * connection state machine merely for diagnostics"). Every `record*`
 * function here is narrow and typed - none accepts a raw free-text message.
 * EndpointId is operator metadata, but its shape is checked again by
 * [DiagnosticSanitizer] before support export.
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
        var typedProbeFailureReason: DiagnosticFailureReason? = null
        var attemptOrdinal: Int = 0
        var attemptIdentity: AttemptEndpointIdentity? = null
        var directTransportAttempted: Boolean = false
        var relayIngressAttempted: Boolean = false
        var relayExitAttempted: Boolean = false
        var currentAttemptFailed: Boolean = false
        var isReconnectIncident: Boolean = false
        val events = mutableListOf<DiagnosticEvent>()
    }

    private var open: OpenSession? = null

    /** Currently-open session id, or null - lets a caller correlate a live UI state with the session being built, without reading store internals. */
    fun currentSessionId(): String? = open?.sessionId

    /** The Auto execution owner, not the health collector, closes an Auto connect sequence. Reconnect incidents keep their existing health-owned lifecycle. */
    fun isAutoConnectSessionOpen(): Boolean = open?.let {
        it.context.gatewaySelectionMode == GatewaySelectionMode.AUTO && !it.isReconnectIncident
    } == true

    fun isReconnectIncidentOpen(): Boolean = open?.isReconnectIncident == true

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

    /** PR #43 review fix - takes the closed [ManifestSourceKind] vocabulary, never a raw free-text label (see [mapManifestSourceToManifestSourceKind] for how a caller derives it from the real [net.pocvpn.client.reachability.ManifestSource]?). */
    fun recordManifestSourceSelected(source: ManifestSourceKind) =
        record(DiagnosticEventType.MANIFEST_SOURCE_SELECTED, mapOf(TAG_SOURCE to source.name))

    fun recordCandidateRanked(candidateCount: Int) =
        record(DiagnosticEventType.CANDIDATE_RANKED, mapOf(TAG_COUNT to candidateCount.toString()))

    /** Also pins [pathKind]/[transportKind] as the session's own selected-path fields (task A) - the LAST attempt started wins, matching which attempt a session's terminal outcome actually describes. */
    fun recordCandidateAttemptStarted(pathKind: PathKind, transportKind: TransportKind, identity: AttemptEndpointIdentity? = null) {
        open?.selectedPathKind = pathKind
        open?.selectedTransportKind = transportKind
        open?.typedProbeFailureReason = null
        open?.attemptOrdinal = (open?.attemptOrdinal ?: 0) + 1
        open?.attemptIdentity = identity
        open?.directTransportAttempted = false
        open?.relayIngressAttempted = false
        open?.relayExitAttempted = false
        open?.currentAttemptFailed = false
        record(DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED, mapOf(TAG_PATH_KIND to pathKind.name, TAG_TRANSPORT_KIND to transportKind.name) + attemptTags())
    }

    /** Called at VpnController's actual transport.connect boundary, never from resolution or a permission prompt. */
    fun recordTransportAttemptStarted(endpointId: EndpointId, transportKind: TransportKind) {
        val session = open ?: return
        when (val identity = session.attemptIdentity) {
            is AttemptEndpointIdentity.Direct -> {
                if (identity.endpointId != endpointId) return
                session.directTransportAttempted = true
            }
            is AttemptEndpointIdentity.Relayed -> {
                if (identity.ingressEndpointId != endpointId) return
                session.relayIngressAttempted = true
            }
            null -> return
        }
        record(DiagnosticEventType.TRANSPORT_START, mapOf(TAG_TRANSPORT_KIND to transportKind.name) + attemptTags())
    }

    /** Marks the endpoint already owned by an in-place reconnect (AWG); no new TRANSPORT_START is fabricated. */
    fun recordActiveEndpointRecovery(endpointId: EndpointId) {
        val session = open ?: return
        when (val identity = session.attemptIdentity) {
            is AttemptEndpointIdentity.Direct -> if (identity.endpointId == endpointId) session.directTransportAttempted = true
            is AttemptEndpointIdentity.Relayed -> if (identity.ingressEndpointId == endpointId) {
                session.relayIngressAttempted = true
                session.relayExitAttempted = true
            }
            null -> Unit
        }
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

    fun recordRelayEndToEndProofResult(success: Boolean, category: RelayFailureCategory?, failureKind: RelayProbeFailureKind? = null) {
        record(
            DiagnosticEventType.RELAY_END_TO_END_PROOF_RESULT,
            buildMap {
                put(TAG_SUCCESS, success.toString())
                category?.let {
                    put(TAG_FAILURE_REASON, mapRelayProbeFailureForPath(it, failureKind, open?.selectedPathKind ?: PathKind.NONE, open?.selectedTransportKind).name)
                }
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
    fun recordPathFailed(reason: DiagnosticFailureReason) {
        record(DiagnosticEventType.PATH_FAILED, mapOf(TAG_FAILURE_REASON to reason.name) + attemptTags())
        open?.currentAttemptFailed = true
    }

    /** The execution observer knows this attempt failed, but has no new typed cause to classify. */
    fun recordAttemptFailed() {
        record(DiagnosticEventType.PATH_FAILED, attemptTags())
        open?.currentAttemptFailed = true
    }

    /** B36: same B29 event, using the currently pinned attempt's path/transport. */
    fun recordRelayPathFailed(category: RelayFailureCategory, failureKind: RelayProbeFailureKind? = null) {
        val reason = mapRelayProbeFailureForPath(category, failureKind, open?.selectedPathKind ?: PathKind.NONE, open?.selectedTransportKind)
        if (failureKind != null && reason != mapRelayFailureForPath(category, open?.selectedPathKind ?: PathKind.NONE, open?.selectedTransportKind)) {
            open?.typedProbeFailureReason = reason
        }
        recordPathFailed(reason)
    }

    /** NON-TERMINAL - see [recordPathFailed]'s own docs; a control-plane exchange (e.g. one relay activation network call) failed, but the combined sequence may still continue with a different candidate. */
    fun recordControlPlaneFailure(reason: DiagnosticFailureReason) =
        record(DiagnosticEventType.CONTROL_PLANE_FAILURE, mapOf(TAG_FAILURE_REASON to reason.name))

    /** TERMINAL - the whole connect() request is now genuinely exhausted: restriction evidence suspected a fixed allowlist and no eligible relay existed at all (checked before any candidate attempt even starts - see [net.pocvpn.client.MainViewModel.connectAuto]'s own docs). */
    fun finishRestrictedNetworkExhaustion() {
        record(DiagnosticEventType.RESTRICTED_NETWORK_EXHAUSTION)
        finish(DiagnosticOutcome.FAILED, DiagnosticFailureReason.RESTRICTED_NETWORK_NO_VIABLE_RELAY)
    }

    /** TERMINAL - the whole connect() request ends in failure, for [reason] - see [recordPathFailed]'s own docs for the non-terminal, per-candidate counterpart. */
    fun finishFailed(reason: DiagnosticFailureReason) {
        val finalReason = if (reason == DiagnosticFailureReason.NO_CANDIDATE || reason == DiagnosticFailureReason.INTERNAL_ERROR || reason == DiagnosticFailureReason.GATEWAY_UNREACHABLE)
            open?.typedProbeFailureReason ?: reason else reason
        if (open?.attemptOrdinal != 0 && open?.currentAttemptFailed == false) recordPathFailed(finalReason)
        finish(DiagnosticOutcome.FAILED, finalReason)
    }

    /** B36: preserve generic failure mapping unless a typed CDN/XHTTP fact exists. */
    fun finishFailedFromTransport(error: VpnError?, failureKind: TransportFailureKind?) {
        val pathKind = open?.selectedPathKind ?: PathKind.NONE
        val transportKind = open?.selectedTransportKind
        val reason = mapTransportFailureForPath(failureKind, pathKind, transportKind)
            ?: open?.typedProbeFailureReason
            ?: error?.let(::mapVpnErrorToFailureReason)
            ?: DiagnosticFailureReason.INTERNAL_ERROR
        finishFailed(reason)
    }

    /** TERMINAL - records [DiagnosticEventType.VPN_PROTECTED] (also, redundantly per requirement B's own vocabulary, [DiagnosticEventType.PATH_SUCCEEDED]) and finishes the session as [DiagnosticOutcome.PROTECTED]. */
    fun finishProtected() {
        val tags = attemptTags(pathProtected = true)
        record(DiagnosticEventType.PATH_SUCCEEDED, tags)
        record(DiagnosticEventType.VPN_PROTECTED, tags)
        finish(DiagnosticOutcome.PROTECTED, null)
    }

    /** TERMINAL - no-op if no session is open (an ordinary disconnect after a session already finished, or before one ever started - never a spurious empty session). */
    fun finishDisconnected() {
        if (open == null) return
        record(DiagnosticEventType.VPN_DISCONNECTED)
        finish(DiagnosticOutcome.DISCONNECTED, null)
    }

    // B30 (task 8) - resilient activation/control-plane diagnostics. Every
    // function below takes only closed enums/ints - never [ControlPlaneOrigin]
    // itself (which carries a raw host) and never a raw String - so, exactly
    // like every record* function above, none of these can carry a
    // hostname/IP/URL/credential/UUID/token into a tag. [originIndex] is the
    // origin's ordinal position in the trusted origin list actually tried
    // (0 = primary), never the host itself - enough for a human reading a
    // bundle to see "origin 2 of 2 failed", never which literal address that was.

    fun recordActivationStarted(gatewayId: ProductionGatewayId) =
        record(DiagnosticEventType.ACTIVATION_STARTED, mapOf(TAG_GATEWAY to gatewayId.name))

    fun recordControlOriginAttempt(gatewayId: ProductionGatewayId, originIndex: Int) =
        record(DiagnosticEventType.CONTROL_ORIGIN_ATTEMPT, mapOf(TAG_GATEWAY to gatewayId.name, TAG_ORIGIN_INDEX to originIndex.toString()))

    fun recordControlOriginFailed(gatewayId: ProductionGatewayId, originIndex: Int, reason: ControlPlaneFailureReason) =
        record(
            DiagnosticEventType.CONTROL_ORIGIN_FAILED,
            mapOf(
                TAG_GATEWAY to gatewayId.name,
                TAG_ORIGIN_INDEX to originIndex.toString(),
                TAG_FAILURE_REASON to mapControlPlaneFailureReasonToFailureReason(reason).name,
            ),
        )

    fun recordControlOriginSucceeded(gatewayId: ProductionGatewayId, originIndex: Int) =
        record(DiagnosticEventType.CONTROL_ORIGIN_SUCCEEDED, mapOf(TAG_GATEWAY to gatewayId.name, TAG_ORIGIN_INDEX to originIndex.toString()))

    fun recordActivationSucceeded(gatewayId: ProductionGatewayId) =
        record(DiagnosticEventType.ACTIVATION_SUCCEEDED, mapOf(TAG_GATEWAY to gatewayId.name))

    /** NON-TERMINAL - same reasoning as [recordPathFailed]: labels one activation attempt's own failure; the caller decides whether/how the enclosing session finishes. */
    fun recordActivationFailed(reason: ControlPlaneFailureReason) =
        record(DiagnosticEventType.ACTIVATION_FAILED, mapOf(TAG_FAILURE_REASON to mapControlPlaneFailureReasonToFailureReason(reason).name))

    // profile-fetch events carry no gateway/endpoint tag - they are used by
    // BOTH gateway-scoped Xray/TLS profile fetch (activation-time,
    // ProductionGatewayId-keyed) and ingress-profile fetch
    // (IngressProfileProvisioner, EndpointId-keyed, not necessarily one of
    // the two production gateways at all) - a single closed identity model
    // that fit one would misrepresent the other, so neither is recorded
    // here (consistent with this file's own "no origin hostname/IP" rule -
    // an EndpointId is not secret, but is also not needed to answer "did a
    // profile fetch succeed").
    fun recordProfileFetchStarted() = record(DiagnosticEventType.PROFILE_FETCH_STARTED)

    fun recordProfileFetchFailed(reason: ControlPlaneFailureReason) =
        record(DiagnosticEventType.PROFILE_FETCH_FAILED, mapOf(TAG_FAILURE_REASON to mapControlPlaneFailureReasonToFailureReason(reason).name))

    fun recordProfileFetchSucceeded() = record(DiagnosticEventType.PROFILE_FETCH_SUCCEEDED)

    /**
     * B30 (task 5) - an existing, still-valid local activation/profile was
     * reused instead of a network refresh (e.g.
     * [net.pocvpn.client.relay.IngressProfileProvisioner.ensureFreshProfile]'s
     * own `stillGood` branch) - never a partial/expired/unsigned substitute,
     * the caller's own freshness check already guarantees that. No
     * gateway/endpoint tag for the same reason [recordProfileFetchStarted]
     * has none - this event is reused by both gateway-scoped and
     * endpoint-scoped callers.
     */
    fun recordOfflineStateReused() = record(DiagnosticEventType.OFFLINE_STATE_REUSED)

    // B30C - mid-session incident capture. Caller starts a NEW session (via
    // [startSession], same as any other real attempt) then calls this ONE
    // extra event to label it as a reconnect incident rather than a fresh
    // connect() request - see [DiagnosticEventType.RECONNECT_INCIDENT_STARTED]'s
    // own docs. The session still terminates through the existing
    // [finishProtected]/[finishFailed]/[finishDisconnected] - no new outcome
    // vocabulary needed.
    fun recordReconnectIncidentStarted() {
        open?.isReconnectIncident = true
        record(DiagnosticEventType.RECONNECT_INCIDENT_STARTED)
    }

    private fun record(type: DiagnosticEventType, tags: Map<String, String> = emptyMap()) {
        val session = open ?: return
        // Task D's own per-session bound (see DiagnosticSession.MAX_EVENTS_PER_SESSION) - a runaway retry loop can never grow one session's timeline unboundedly.
        if (session.events.size >= DiagnosticSession.MAX_EVENTS_PER_SESSION) return
        session.events.add(DiagnosticEvent(type, nowProvider(), tags))
    }

    private fun attemptTags(pathProtected: Boolean = false): Map<String, String> {
        val session = open ?: return emptyMap()
        if (session.attemptOrdinal == 0) return emptyMap()
        return buildMap {
            put(TAG_ATTEMPT_ORDINAL, session.attemptOrdinal.toString())
            when (val identity = session.attemptIdentity) {
                is AttemptEndpointIdentity.Direct -> {
                    put(TAG_PLANNED_ENDPOINT_ID, identity.endpointId.value)
                    if (session.directTransportAttempted) put(TAG_ATTEMPTED_ENDPOINT_ID, identity.endpointId.value)
                }
                is AttemptEndpointIdentity.Relayed -> {
                    put(TAG_PLANNED_INGRESS_ENDPOINT_ID, identity.ingressEndpointId.value)
                    put(TAG_PLANNED_EXIT_ENDPOINT_ID, identity.exitEndpointId.value)
                    if (session.relayIngressAttempted) put(TAG_ATTEMPTED_INGRESS_ENDPOINT_ID, identity.ingressEndpointId.value)
                    if (pathProtected || session.relayExitAttempted) put(TAG_ATTEMPTED_EXIT_ENDPOINT_ID, identity.exitEndpointId.value)
                }
                null -> Unit // Legacy callers/sessions have unknown endpoint identity.
            }
        }
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
        const val TAG_GATEWAY = "gateway"
        const val TAG_ORIGIN_INDEX = "originIndex"
        const val TAG_ATTEMPT_ORDINAL = "attemptOrdinal"
        const val TAG_PLANNED_ENDPOINT_ID = "plannedEndpointId"
        const val TAG_ATTEMPTED_ENDPOINT_ID = "attemptedEndpointId"
        const val TAG_PLANNED_INGRESS_ENDPOINT_ID = "plannedIngressEndpointId"
        const val TAG_ATTEMPTED_INGRESS_ENDPOINT_ID = "attemptedIngressEndpointId"
        const val TAG_PLANNED_EXIT_ENDPOINT_ID = "plannedExitEndpointId"
        const val TAG_ATTEMPTED_EXIT_ENDPOINT_ID = "attemptedExitEndpointId"
    }
}
