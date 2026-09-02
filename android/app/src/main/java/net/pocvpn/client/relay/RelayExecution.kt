package net.pocvpn.client.relay

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.VpnTransport

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
     * [RelayIngressResolver]'s own docs) without a server-side readiness
     * signal channel, which does not exist yet - this stage exists in the
     * typed vocabulary for when that channel is built, and so a future
     * implementation can report it honestly rather than the model having no
     * name for it at all.
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

    /** B24 - this client build has no real [RelayIngressResolver] implementation wired (see that interface's own docs) - never a fabricated attempt outcome. */
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
 * B24 review fix (PR #38, round 3 - ownership boundary) - what
 * [RelayIngressResolver.resolve] returns: EITHER the ingredients needed to
 * feed the EXISTING `TransportOrchestrator`/`VpnController` dial path (never
 * a live tunnel, never a state claim), or a typed reason it cannot be
 * prepared at all.
 *
 * This is the architectural correction to an earlier version of this file,
 * which had the resolver's own return value BE the terminal attempt
 * outcome (including a `Success` case) - meaning a real implementation
 * would have had to independently drive the tunnel to
 * `END_TO_END_DATA_PLANE_OK` and report back, making it a SECOND VPN
 * execution/state authority beside `VpnController`. That was fixed before
 * any real implementation was built on it: `RelayIngressResolver` now only
 * ever prepares data - actual tunnel start/stop and Connected/Protected
 * state ownership stay entirely with `TransportOrchestrator`/
 * `VpnController`/the existing `VpnService`, the SAME single ownership path
 * Direct already uses (task requirement 1/2/3 - "no second connection
 * controller").
 */
sealed class RelayIngressResolution {
    /**
     * The real, already-constructed [VpnTransport] (and the [TransportKind]
     * it implements) to dial for the client<->ingress hop, pinned to
     * [RelayedExecutionPlan.ingressBinding]/[RelayedExecutionPlan
     * .ingressTransport] - reuses the EXISTING Xray transport/service stack
     * (task requirement 4/7), never a bespoke networking path. Handing this
     * to `TransportOrchestrator.resolve`/`VpnController.connect` is the
     * CALLER's job (`MainViewModel`) - this type carries no state of its
     * own and starts nothing by existing.
     */
    data class Resolved(val transport: VpnTransport, val kind: TransportKind) : RelayIngressResolution()

    /** No real ingress client profile/credential is available to prepare a dial with - a typed reason, never a fabricated attempt. */
    data class NotProvisioned(val category: RelayFailureCategory, val detail: String? = null) : RelayIngressResolution()
}

/**
 * B24 review fix (PR #38, round 3) - the real client<->ingress PREPARATION
 * boundary a future implementation fulfills: given a pinned
 * [RelayedExecutionPlan], produce either a real [VpnTransport] ready to be
 * dialed through the existing `TransportOrchestrator`/`VpnController` path,
 * or a typed reason it cannot be (see [RelayIngressResolution]'s own docs
 * for exactly why this is a RESOLVER, not a dialer that owns state).
 *
 * Deliberately has NO production implementation in this slice: preparing an
 * ingress Xray transport over XRAY_REALITY/TLS_TCP requires a real,
 * per-ingress-provisioned Xray client profile (the SAME per-endpoint
 * credential discipline `VpnController` already requires for a real
 * gateway - see PROJECT_ARCHITECTURE.md's Xray address-authority note), and
 * no such profile can exist for an ingress that isn't deployed and that no
 * device has been activated against (task's own "no new infrastructure"
 * constraint this slice). [NotProvisionedRelayIngressResolver] is the ONLY
 * implementation wired into production - it reports [RelayIngressResolution
 * .NotProvisioned] for every plan, honestly, rather than attempting to
 * prepare a transport with no real credential behind it (which would
 * either crash outright or, worse, silently misbehave). A future slice
 * that deploys a real ingress and wires per-ingress activation supplies a
 * real implementation here that constructs a real Xray transport from that
 * profile - the call site in `MainViewModel` (feed the result into
 * `TransportOrchestrator`/`VpnController`, exactly like Direct) never
 * changes.
 */
fun interface RelayIngressResolver {
    suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution
}

/** B24 - the production default: reports [RelayIngressResolution.NotProvisioned] for every plan, honestly (see [RelayIngressResolver]'s own docs). Never simulates a transport, never simulates traffic. */
object NotProvisionedRelayIngressResolver : RelayIngressResolver {
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution = RelayIngressResolution.NotProvisioned(
        category = RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
        detail = "no RelayIngressResolver is provisioned for ingress ${plan.ingressEndpointId.value}",
    )
}
