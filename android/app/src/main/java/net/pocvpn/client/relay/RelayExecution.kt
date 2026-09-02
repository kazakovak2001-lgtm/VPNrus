package net.pocvpn.client.relay

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind

/**
 * B24 - the real, immutable client-side execution contract for one relayed
 * attempt: client -> INGRESS ([ingressBinding], over [ingressTransport]) ->
 * EXIT ([exitBinding], over [exitTransport]) -> Internet. [from] is the ONLY
 * intended constructor for a real attempt: it copies every field straight
 * off an already-ranked [AutoGatewaySelector.RelayAttemptCandidate]'s own
 * pinned facts - NEVER by re-resolving endpoint/binding facts from a
 * manifest or catalog mid-attempt (the same B16/B23 attempt-pinning
 * invariant [net.pocvpn.client.smartconnect.GatewayAttemptCandidate
 * .configSnapshot] already enforces for Direct). [historyPathId] is carried
 * through so [net.pocvpn.client.reachability.PathHistoryStore] recording
 * after this attempt is scoped to the FULL relayed path (see that
 * property's own docs on [net.pocvpn.client.reachability.PathCandidate
 * .historyPathId]) - never a single hop, and never conflated with Direct
 * history for either endpoint.
 */
data class RelayedExecutionPlan(
    val ingressEndpointId: EndpointId,
    val ingressBinding: EndpointTransportBinding,
    val ingressTransport: TransportKind,
    val exitEndpointId: EndpointId,
    val exitBinding: EndpointTransportBinding,
    val exitTransport: TransportKind,
    val historyPathId: String,
) {
    companion object {
        fun from(candidate: AutoGatewaySelector.RelayAttemptCandidate): RelayedExecutionPlan = RelayedExecutionPlan(
            ingressEndpointId = candidate.ingressEndpointId,
            ingressBinding = candidate.ingressBinding,
            ingressTransport = candidate.ingressTransport,
            exitEndpointId = candidate.exitEndpointId,
            exitBinding = candidate.exitBinding,
            exitTransport = candidate.exitTransport,
            historyPathId = candidate.historyPathId,
        )
    }
}

/**
 * B24 - task requirement 10's typed readiness stages, most conservative
 * first. A process starting or a TCP/UDP socket opening is NOT readiness -
 * see [RelayAttemptOutcome]'s own docs for why only [END_TO_END_DATA_PLANE_OK]
 * may ever produce healthy/Protected-eligible evidence, reusing the exact
 * B21 lesson this codebase already learned for Direct transports ("never
 * return Protected merely because a process/socket started").
 */
enum class RelayReadinessStage {
    /** [ReachabilityEngine]-level evidence only - the ingress endpoint/transport pairing looks reachable, no attempt made yet. */
    INGRESS_REACHABLE,

    /** The client's own transport handshake to the INGRESS succeeded - says nothing about the ingress's own upstream link to the EXIT. */
    INGRESS_HANDSHAKE_OK,

    /**
     * The ingress's own encrypted upstream connection to the EXIT
     * succeeded. NOT directly observable from the client's own socket-level
     * view today (the client dials only the ingress - see
     * [RelayIngressDialer]'s own docs) without a server-side readiness
     * signal channel, which does not exist yet - this stage exists in the
     * typed vocabulary for when that channel is built, and so a future
     * dialer can report it honestly rather than the model having no name
     * for it at all.
     */
    UPSTREAM_EXIT_HANDSHAKE_OK,

    /** Real bidirectional application data confirmed flowing client->ingress->exit->Internet - the ONLY stage [RelayAttemptOutcome.isHealthy] accepts. */
    END_TO_END_DATA_PLANE_OK,
}

/** B24 - task requirement 12's typed relay failure categories - never collapsed into one generic "handshake timeout". */
enum class RelayFailureCategory {
    INGRESS_UNREACHABLE,
    INGRESS_HANDSHAKE_FAILED,
    UPSTREAM_EXIT_UNREACHABLE,
    UPSTREAM_EXIT_HANDSHAKE_FAILED,
    RELAY_AUTH_FAILED,
    END_TO_END_DATA_PLANE_FAILED,

    /** B24 - this client build has no real [RelayIngressDialer] implementation wired (see that interface's own docs) - never a fabricated attempt outcome. */
    EXECUTION_NOT_IMPLEMENTED,
}

/**
 * B24 - the result of one real relayed attempt. [Success] is constructible
 * ONLY when [RelayReadinessStage.END_TO_END_DATA_PLANE_OK] was genuinely
 * reached - there is no code path that can construct a healthy outcome from
 * a lower stage, which is what makes [isHealthy] fail-closed by
 * CONSTRUCTION rather than by convention.
 */
sealed class RelayAttemptOutcome {
    abstract val plan: RelayedExecutionPlan
    abstract val highestStageReached: RelayReadinessStage?

    data class Success(override val plan: RelayedExecutionPlan) : RelayAttemptOutcome() {
        override val highestStageReached: RelayReadinessStage = RelayReadinessStage.END_TO_END_DATA_PLANE_OK
    }

    data class Failure(
        override val plan: RelayedExecutionPlan,
        override val highestStageReached: RelayReadinessStage?,
        val category: RelayFailureCategory,
        val detail: String? = null,
    ) : RelayAttemptOutcome() {
        init {
            require(highestStageReached != RelayReadinessStage.END_TO_END_DATA_PLANE_OK) {
                "END_TO_END_DATA_PLANE_OK must be reported as Success, never Failure"
            }
        }
    }

    /** Fail-closed by construction (task requirement 10/H): true if and only if this is [Success]. */
    val isHealthy: Boolean get() = this is Success
}

/**
 * B24 - the real client<->ingress execution boundary a future transport
 * implementation fulfills. Deliberately has NO production implementation in
 * this slice: dialing an ingress over XRAY_REALITY/TLS_TCP requires a real,
 * per-ingress-provisioned Xray client profile (the SAME per-endpoint
 * credential discipline `VpnController` already requires for a real
 * gateway - see PROJECT_ARCHITECTURE.md's Xray address-authority note), and
 * no such profile can exist for an ingress that isn't deployed and that no
 * device has been activated against (task's own "no new infrastructure"
 * constraint this slice). [NotProvisionedRelayIngressDialer] is the ONLY
 * implementation wired into production - it fails closed for every plan,
 * honestly, rather than attempting a connection with no real credential
 * behind it (which would either crash outright or, worse, silently
 * misbehave). A future slice that deploys a real ingress and wires
 * per-ingress activation supplies a real implementation here - the call
 * site in `MainViewModel` never changes.
 */
fun interface RelayIngressDialer {
    suspend fun dial(plan: RelayedExecutionPlan): RelayAttemptOutcome
}

/** B24 - the production default: fails closed, honestly, for every plan (see [RelayIngressDialer]'s own docs). Never simulates traffic. */
object NotProvisionedRelayIngressDialer : RelayIngressDialer {
    override suspend fun dial(plan: RelayedExecutionPlan): RelayAttemptOutcome = RelayAttemptOutcome.Failure(
        plan = plan,
        highestStageReached = null,
        category = RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
        detail = "no RelayIngressDialer is provisioned for ingress ${plan.ingressEndpointId.value}",
    )
}
