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

    /** B25 (task E/F/K) - no [IngressProfileStore] entry exists at all for this ingress endpoint - the device has never been activated against it. */
    PROFILE_NOT_PROVISIONED,

    /** B25 (task E/F/K) - a profile exists for this ingress endpoint, but its pinned endpoint/binding/transport does not match the current [RelayedExecutionPlan] (see [IngressClientProfile.matches]) - never used anyway, fails closed rather than silently re-binding. */
    PROFILE_MISMATCH,

    /** B25 (task E/F/K) - a matching profile exists but its [IngressClientProfile.expiresAtEpochMillis] has passed. */
    PROFILE_EXPIRED,

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
    data class Resolved(
        val transport: VpnTransport,
        val kind: TransportKind,
        // B25 (task C) - the SAME already-loaded, already-validated
        // IngressClientProfile [RelayIngressResolverImpl] matched against
        // this plan - carried alongside the transport so a caller (armFailoverWatch)
        // never has to re-resolve the profile store mid-attempt to find the
        // real end-to-end proof coordinates ([IngressClientProfile.endToEndProbeUrl]/
        // [IngressClientProfile.endToEndProbeToken]) - same attempt-pinning
        // discipline every other resolved fact in this file already follows.
        val profile: IngressClientProfile,
    ) : RelayIngressResolution()

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

/**
 * B25 (task C) - the result of the real end-to-end data-plane proof: the
 * ONLY signal that may ever promote a relayed session's
 * [RelayReadinessStage] past [RelayReadinessStage.INGRESS_HANDSHAKE_OK].
 * [Success] means real traffic was confirmed to have traversed
 * client -> ingress -> exit -> the probe target (never a process-running
 * check, an open socket, or an ingress-only handshake - the task's own
 * explicit "do NOT accept" list).
 */
sealed class RelayProbeResult {
    object Success : RelayProbeResult()
    data class Failure(val category: RelayFailureCategory, val detail: String? = null) : RelayProbeResult()
}

/**
 * B25 (task C) - the real client/server contract proving the upstream and
 * end-to-end relay stages: given the pinned [RelayedExecutionPlan] and the
 * already-matched [IngressClientProfile] for it (never re-resolved from the
 * store mid-attempt - same pinning discipline as everything else in this
 * file), ask whatever real proof channel the control-plane issued whether
 * client -> ingress -> exit -> Internet is genuinely functional RIGHT NOW,
 * over the tunnel this attempt just brought up (never before the transport
 * reports [net.pocvpn.client.vpn.TransportState.Connected] for the ingress
 * hop - see [net.pocvpn.client.MainViewModel]'s `armFailoverWatch` for the
 * one real call site).
 */
fun interface RelayEndToEndProbe {
    suspend fun probe(plan: RelayedExecutionPlan, profile: IngressClientProfile): RelayProbeResult
}

/**
 * B25 - the honest default: no real proof channel is wired, so every probe
 * fails closed with [RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED] -
 * never a fabricated success. A relayed session can only ever reach
 * [RelayReadinessStage.END_TO_END_DATA_PLANE_OK]/Protected once a caller
 * explicitly wires [HttpRelayEndToEndProbe] (or an equivalent real
 * implementation) against a real ingress deployment - see that class's own
 * docs.
 */
object NotConfiguredRelayEndToEndProbe : RelayEndToEndProbe {
    override suspend fun probe(plan: RelayedExecutionPlan, profile: IngressClientProfile): RelayProbeResult =
        RelayProbeResult.Failure(
            category = RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
            detail = "no RelayEndToEndProbe is configured for ingress ${plan.ingressEndpointId.value}",
        )
}

/**
 * B25 (task C) - the real implementation: performs a genuine HTTPS GET to
 * [IngressClientProfile.endToEndProbeUrl] carrying
 * [IngressClientProfile.endToEndProbeToken] as a bearer credential, over
 * whatever socket/route the OS resolves at call time - since this is only
 * ever invoked AFTER the ingress transport reports a real
 * [net.pocvpn.client.vpn.TransportState.Connected] handshake (see
 * [RelayEndToEndProbe]'s own docs), ordinary OS routing sends this request
 * through the just-established tunnel interface exactly like any other app
 * traffic would - never a bespoke socket-binding hack. [endToEndProbeUrl]
 * is the control-plane's own authenticated internal readiness endpoint
 * (task requirement C's first accepted option) - reachable in practice only
 * because this request actually traverses ingress -> exit, so a real,
 * non-fabricated 200 response is only obtainable when that path genuinely
 * works end to end. A disconnected/rebuilt socket, non-200 status, or a
 * response body that fails [expectedBodyMarker] all fail closed - this
 * function NEVER returns [RelayProbeResult.Success] merely because a
 * connection was accepted (no "TCP connect == healthy", the same B21 lesson
 * [RelayReadinessStage]'s own docs already reference).
 *
 * No profile ([IngressClientProfile.endToEndProbeUrl] null) is reported as
 * [RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED], never silently skipped
 * as success.
 */
class HttpRelayEndToEndProbe(
    private val connectTimeoutMillis: Int = 5_000,
    private val readTimeoutMillis: Int = 5_000,
) : RelayEndToEndProbe {
    override suspend fun probe(plan: RelayedExecutionPlan, profile: IngressClientProfile): RelayProbeResult {
        val urlString = profile.endToEndProbeUrl
            ?: return RelayProbeResult.Failure(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED, "profile carries no end-to-end probe URL")
        return try {
            val url = java.net.URL(urlString)
            if (url.protocol != "https") {
                return RelayProbeResult.Failure(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, "refusing a non-HTTPS probe URL")
            }
            val connection = (url.openConnection() as java.net.HttpURLConnection).apply {
                requestMethod = "GET"
                connectTimeout = connectTimeoutMillis
                readTimeout = readTimeoutMillis
                useCaches = false
                setRequestProperty("Cache-Control", "no-store")
                profile.endToEndProbeToken?.let { token -> setRequestProperty("Authorization", "Bearer $token") }
            }
            try {
                val status = connection.responseCode
                if (status != java.net.HttpURLConnection.HTTP_OK) {
                    return RelayProbeResult.Failure(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, "probe returned HTTP $status")
                }
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                if (!body.contains(plan.historyPathId)) {
                    return RelayProbeResult.Failure(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, "probe response did not echo this session's path identity")
                }
                RelayProbeResult.Success
            } finally {
                connection.disconnect()
            }
        } catch (e: java.net.SocketTimeoutException) {
            RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, e.javaClass.simpleName)
        } catch (e: java.io.IOException) {
            RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, e.javaClass.simpleName)
        } catch (e: Exception) {
            RelayProbeResult.Failure(RelayFailureCategory.END_TO_END_DATA_PLANE_FAILED, e.javaClass.simpleName)
        }
    }
}
