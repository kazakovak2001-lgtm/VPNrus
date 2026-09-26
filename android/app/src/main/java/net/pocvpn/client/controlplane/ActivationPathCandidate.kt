package net.pocvpn.client.controlplane

import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B67.2 - the three architectural ACTIVATION / CONTROL-PLANE path shapes this
 * codebase recognizes (task's own required vocabulary, distinct from any
 * DATA-PLANE path type such as [net.pocvpn.client.reachability.PathCandidate]/
 * [net.pocvpn.client.reachability.IngressKind] - see [ActivationPathCandidate]'s
 * own docs for why the two are never conflated):
 *
 *  - [DIRECT] - the client dials the gateway's own control-plane host
 *    directly (today's only real, deployed shape - see
 *    [ControlPlaneOriginSetBuilder]).
 *  - [CHAIN_DIRECT] - a trusted, non-CDN ingress/relay in front of the
 *    control-plane host.
 *  - [CHAIN_CDN] - a trusted CDN-fronted edge in front of the control-plane
 *    host.
 *
 * The ordinal/declaration order (DIRECT, CHAIN_DIRECT, CHAIN_CDN) IS the
 * fixed, deterministic preference [ActivationPathCandidateBuilder] composes
 * candidates in - not a score. There is no local evidence (no reachability
 * history, no restriction classification) this codebase trusts for ranking
 * an ACTIVATION path today - control-plane reachability is not the same
 * fact as DATA-PLANE endpoint reachability [net.pocvpn.client.reachability
 * .PathScorer] ranks, and reusing that scorer's evidence here would silently
 * conflate the two. Per task instruction ("when there is no useful evidence
 * to distinguish paths, preserve stable deterministic ordering rather than
 * inventing a preference"), simplest-first is that stable order: a direct
 * dial is preferred when trusted and available, falling back to a trusted
 * relay, and only then to a trusted CDN front.
 */
enum class ActivationPathKind { DIRECT, CHAIN_DIRECT, CHAIN_CDN }

/**
 * B67.2 - one ACTIVATION-PATH-SHAPE's own trusted origin set: every
 * [ControlPlaneOrigin] this [kind] resolves to for one gateway, TODAY (see
 * [ActivationPathCandidateBuilder] for how this is composed). [origins] is
 * never empty - a shape with no trusted origin today simply has no
 * candidate at all (see [ActivationPathCandidateBuilder.forGateway]), so a
 * caller never has to special-case an empty candidate.
 *
 * Deliberately NOT a data-plane [net.pocvpn.client.reachability.PathCandidate]
 * - this models "how the CLIENT reaches the CONTROL PLANE for /v1/activate",
 * a different question from "how does traffic reach the Internet through a
 * gateway". The two may one day share physical infrastructure (e.g. the same
 * CDN edge could front both), but that is an operational fact about future
 * deployment, not something this type conflates architecturally: a
 * [ControlPlaneOrigin] carries only [ProductionGatewayId] + host, never an
 * [net.pocvpn.client.reachability.EndpointDescriptor]/transport binding.
 */
data class ActivationPathCandidate(val kind: ActivationPathKind, val origins: List<ControlPlaneOrigin>) {
    init {
        require(origins.isNotEmpty()) { "ActivationPathCandidate requires at least one trusted origin" }
        require(origins.all { it.gatewayId == origins.first().gatewayId }) {
            "ActivationPathCandidate origins must all target the same gateway"
        }
    }

    val gatewayId: ProductionGatewayId get() = origins.first().gatewayId
}

/**
 * B67.2 (task 1) - THE ONE place an ordered [ActivationPathCandidate] list is
 * built for a gateway's activation/control-plane reachability, composing:
 *
 *  1. [ControlPlaneOriginSetBuilder] (existing, unchanged - DIRECT).
 *  2. [TrustedChainControlPlaneOriginCatalog.chainDirect] (CHAIN_DIRECT).
 *  3. [TrustedChainControlPlaneOriginCatalog.chainCdn] (CHAIN_CDN).
 *
 * in that fixed order (see [ActivationPathKind]'s own docs on why this is a
 * deterministic order, never a score). A shape whose builder returns an
 * empty list contributes NO candidate - never an empty-origin placeholder -
 * so [forGateway] returning `[DIRECT]` alone (today's real production
 * catalog: no trusted chain/CDN control-plane origin is deployed yet - see
 * [TrustedChainControlPlaneOriginCatalog]'s own docs) is byte-for-byte the
 * same shape [ControlPlaneOriginSetBuilder.forGateway] alone always produced
 * pre-B67.2 (task requirement 8/"existing single-path behavior unchanged"),
 * once flattened by [ActivationPathOriginSetBuilder].
 *
 * [forGateway] - the ONLY production entry point - takes no origin/host
 * parameter of any kind: there is structurally no argument through which a
 * caller could pass a raw host/URL, exactly like
 * [ControlPlaneOriginSetBuilder] itself - every origin it produces is traced
 * back to a compiled, trusted catalog. This is the ONLY new composition this
 * slice adds; scoring/ranking stays fixed-order (no second scorer), and
 * bounded per-origin execution stays [TrustedOriginRequestExecutor]'s (no
 * second retry engine) - see [ActivationPathOriginSetBuilder]'s own docs for
 * how this feeds the existing [ActivationResilienceCoordinator] unchanged.
 *
 * [forGatewayFromOrigins] is a SEPARATE, `internal` (module-visible only,
 * never reachable from outside this Gradle module, never called by
 * [forGateway] itself or by any production call site such as
 * `MainViewModel`) test seam - it exists ONLY so a deterministic unit test
 * can prove the DIRECT/CHAIN_DIRECT/CHAIN_CDN composition/fallback
 * MECHANISM against synthetic, test-authored [ControlPlaneOrigin] values,
 * the same established pattern [ActivationResilienceCoordinator.activate]'s
 * own `origins` parameter and `MainViewModel`'s own
 * `controlPlaneOriginsForActivation` constructor seam already use elsewhere
 * in this codebase. It is never given a caller-/user-/network-supplied host
 * in this codebase - the one and only caller of it is this module's own test
 * source set.
 */
object ActivationPathCandidateBuilder {
    fun forGateway(gatewayId: ProductionGatewayId): List<ActivationPathCandidate> = forGatewayFromOrigins(
        gatewayId,
        directOrigins = ControlPlaneOriginSetBuilder.forGateway(gatewayId),
        chainDirectOrigins = TrustedChainControlPlaneOriginCatalog.chainDirect(gatewayId),
        chainCdnOrigins = TrustedChainControlPlaneOriginCatalog.chainCdn(gatewayId),
    )

    internal fun forGatewayFromOrigins(
        gatewayId: ProductionGatewayId,
        directOrigins: List<ControlPlaneOrigin>,
        chainDirectOrigins: List<ControlPlaneOrigin>,
        chainCdnOrigins: List<ControlPlaneOrigin>,
    ): List<ActivationPathCandidate> = listOfNotNull(
        directOrigins.takeIf { it.isNotEmpty() }?.let { ActivationPathCandidate(ActivationPathKind.DIRECT, it) },
        chainDirectOrigins.takeIf { it.isNotEmpty() }?.let { ActivationPathCandidate(ActivationPathKind.CHAIN_DIRECT, it) },
        chainCdnOrigins.takeIf { it.isNotEmpty() }?.let { ActivationPathCandidate(ActivationPathKind.CHAIN_CDN, it) },
    )
}

/**
 * B67.2 (task 4) - the flattened [ControlPlaneOrigin] list
 * [ActivationResilienceCoordinator.activate]'s existing `origins` parameter
 * (fed straight into the existing, unmodified
 * [TrustedOriginRequestExecutor]) actually consumes - the ONE integration
 * seam between the new [ActivationPathCandidateBuilder] composition and the
 * existing B30 activation machinery. Deliberately does NOT introduce a
 * second bounded-execution loop: concatenating [ActivationPathCandidateBuilder]'s
 * candidates in order and handing the flat list to the SAME executor already
 * gives exactly the required semantics for free -
 *
 *  - each origin (across every path shape) is attempted at MOST once, in
 *    DIRECT -> CHAIN_DIRECT -> CHAIN_CDN order (bounded by construction -
 *    [TrustedOriginRequestExecutor] already tries `origins.size` origins,
 *    never more);
 *  - [ControlPlaneFailureReason.AUTHORIZATION_REJECTED] on ANY origin (any
 *    path shape) is still terminal for the whole call (existing
 *    `stopOnReasons` default) - a rejected credential is never retried
 *    against a later path shape either, preserving the B30 invariant exactly
 *    as task requirement (AUTHORIZATION RULE) demands;
 *  - a network/connectivity-type failure on every origin of one path shape
 *    simply falls through to the next path shape's own origin(s) in the same
 *    flat loop - no recursive fallback, no second retry engine, nothing
 *    reimplemented.
 *
 * This is the exact place [net.pocvpn.client.MainViewModel]'s own
 * `controlPlaneOriginsForActivation` seam is repointed to (see that class's
 * own docs on that seam) - [ActivationResilienceCoordinator]/
 * [TrustedOriginRequestExecutor]/`MainViewModel.activateDevice()`'s
 * success/persistence/provisioning logic are all completely unmodified by
 * this slice.
 */
object ActivationPathOriginSetBuilder {
    fun forGateway(gatewayId: ProductionGatewayId): List<ControlPlaneOrigin> =
        ActivationPathCandidateBuilder.forGateway(gatewayId).flatMap { it.origins }
}
