package net.pocvpn.client.controlplane

import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B67.2 - THE ONE place CHAIN_DIRECT/CHAIN_CDN [ControlPlaneOrigin]s would be
 * built from, mirroring [ControlPlaneOriginSetBuilder]'s own
 * compiled-trusted-catalog-only discipline: never a caller-supplied host,
 * never inferred from a redirect/response, only a literal compiled fact
 * audited into this file.
 *
 * TODAY's real, compiled production topology deploys no trusted ingress/relay
 * or CDN-fronted host capable of reaching the CONTROL PLANE (`/v1/activate`
 * and friends) - see [net.pocvpn.client.smartconnect.ProductionIngressEndpoints]'s
 * own docs: the one deployed ingress (Stockholm, B25/B31) relays DATA-PLANE
 * VLESS traffic to an EXIT, an entirely different protocol/purpose from the
 * HTTPS control-plane calls [ControlPlaneOrigin]/[TrustedOriginRequestExecutor]
 * make - it is not a trusted control-plane front and must never be reused as
 * one merely because it happens to exist (that would be exactly the kind of
 * data-plane/control-plane conflation task docs warn against). No CDN
 * provider/front has been deployed or audited for control-plane use at all.
 *
 * Both functions therefore return an empty list today - by design, not by
 * omission: [ActivationPathCandidateBuilder.forGateway] already treats an
 * empty list as "this path shape has no candidate right now" (never an
 * empty-origin placeholder that could be executed against nothing), so
 * today's real activation flow is, and remains, DIRECT-only - see that
 * object's own docs on why this keeps task requirement 8 exactly true. The
 * moment ops audits and deploys a genuine trusted relay/CDN front for the
 * control plane, populating the matching function here (from that same
 * compiled, code-reviewed catalog discipline - never any other source) is
 * the ONLY change CHAIN_DIRECT/CHAIN_CDN activation needs to go live; no
 * caller of [ActivationPathCandidateBuilder]/[ActivationPathOriginSetBuilder]/
 * [ActivationResilienceCoordinator] would need to change.
 */
object TrustedChainControlPlaneOriginCatalog {
    fun chainDirect(gatewayId: ProductionGatewayId): List<ControlPlaneOrigin> = emptyList()

    fun chainCdn(gatewayId: ProductionGatewayId): List<ControlPlaneOrigin> = emptyList()
}
