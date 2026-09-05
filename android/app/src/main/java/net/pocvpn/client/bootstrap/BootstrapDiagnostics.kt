package net.pocvpn.client.bootstrap

import net.pocvpn.client.diagnostics.support.DiagnosticEvent
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B36 (task requirement 11) - sanitized, typed bootstrap-flow events,
 * reusing the EXISTING [DiagnosticEvent]/[DiagnosticEventType] vocabulary
 * (never a second, independently-shaped event type - B29's own "labeling
 * vocabulary over real state, never a second state machine" principle,
 * extended here to bootstrap's own real state). Every tag value is an enum
 * name or a small closed literal - NEVER the activation code, an
 * Authorization header, a private key, a UUID/device identity, a raw
 * profile, REALITY private material, a token, or a payload (the exact list
 * task requirement 11 forbids). [ProductionGatewayId] itself is already a
 * closed, non-secret enum (never a host/IP string) - safe to record
 * directly under [TAG_CANDIDATE].
 *
 * Deliberately a SEPARATE, small recorder from
 * [net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder]: that
 * recorder's [net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder.startSession]
 * requires a live network/restriction-classifier snapshot
 * ([net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder.StartContext])
 * that does not exist yet at the point bootstrap runs (before any connect
 * attempt, before Home screen, before RestrictionClassifier has anything to
 * classify against) - forcing bootstrap events through that session model
 * would mean fabricating a fake snapshot, which is worse than a small,
 * purpose-built, equally-sanitized recorder reusing the same event shape.
 * See docs/B36_BOOTSTRAP_PRE_ACTIVATION_TUNNEL.md for the full reasoning.
 */
object BootstrapDiagnosticTags {
    const val TAG_CANDIDATE = "candidate"
    const val TAG_TRANSPORT_KIND = "transport_kind"
    const val TAG_SUCCESS = "success"
    const val TAG_OUTCOME_CATEGORY = "outcome_category"
    const val TAG_ATTEMPTED_COUNT = "attempted_count"
}

/**
 * B36 - the bounded, in-memory sink for bootstrap [DiagnosticEvent]s. Never
 * persisted to disk in this slice (task scope is the smallest coherent
 * bootstrap-tunnel slice, and nothing downstream reads a persisted
 * bootstrap log yet) - a future slice can fold [snapshot] into
 * [net.pocvpn.client.diagnostics.support.SupportBundle] export without
 * changing this recorder's own API.
 */
class BootstrapDiagnosticsRecorder(
    private val nowProvider: () -> Long = System::currentTimeMillis,
) {
    private val events = mutableListOf<DiagnosticEvent>()

    @Synchronized
    private fun record(type: DiagnosticEventType, tags: Map<String, String> = emptyMap()) {
        events += DiagnosticEvent(type = type, atEpochMillis = nowProvider(), tags = tags)
        while (events.size > MAX_EVENTS) events.removeAt(0)
    }

    fun recordAttemptStarted(candidate: ProductionGatewayId, transportKind: TransportKind) {
        record(
            DiagnosticEventType.BOOTSTRAP_ATTEMPT_STARTED,
            mapOf(
                BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name,
                BootstrapDiagnosticTags.TAG_TRANSPORT_KIND to transportKind.name,
            ),
        )
    }

    fun recordConnectResult(candidate: ProductionGatewayId, success: Boolean) {
        record(
            DiagnosticEventType.BOOTSTRAP_CANDIDATE_CONNECT_RESULT,
            mapOf(
                BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name,
                BootstrapDiagnosticTags.TAG_SUCCESS to success.toString(),
            ),
        )
    }

    fun recordBecameUsable(candidate: ProductionGatewayId) {
        record(DiagnosticEventType.BOOTSTRAP_BECAME_USABLE, mapOf(BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name))
    }

    fun recordActivationStarted(candidate: ProductionGatewayId) {
        record(DiagnosticEventType.BOOTSTRAP_ACTIVATION_STARTED, mapOf(BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name))
    }

    /** [outcomeCategory] must already be a closed label (an outcome class's own simple name) - never a raw message. */
    fun recordActivationResult(candidate: ProductionGatewayId, outcomeCategory: String) {
        record(
            DiagnosticEventType.BOOTSTRAP_ACTIVATION_RESULT,
            mapOf(
                BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name,
                BootstrapDiagnosticTags.TAG_OUTCOME_CATEGORY to outcomeCategory,
            ),
        )
    }

    fun recordTeardown(candidate: ProductionGatewayId) {
        record(DiagnosticEventType.BOOTSTRAP_TEARDOWN, mapOf(BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name))
    }

    fun recordUnavailable(attempted: List<ProductionGatewayId>) {
        record(DiagnosticEventType.BOOTSTRAP_UNAVAILABLE, mapOf(BootstrapDiagnosticTags.TAG_ATTEMPTED_COUNT to attempted.size.toString()))
    }

    fun recordProvisionedTransition(candidate: ProductionGatewayId) {
        record(DiagnosticEventType.BOOTSTRAP_PROVISIONED_TRANSITION, mapOf(BootstrapDiagnosticTags.TAG_CANDIDATE to candidate.name))
    }

    @Synchronized
    fun snapshot(): List<DiagnosticEvent> = events.toList()

    private companion object {
        const val MAX_EVENTS = 100
    }
}
