package net.pocvpn.client.activation

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B67.6 - the entitlement -> eligible-gateway mapping.
 *
 * The ONLY signed entitlement-scope signal that exists today is
 * [ActivationEnvelope.bootstrapEndpointHints] - already documented (see that
 * field's own class docs) as non-authoritative: it may only reorder/
 * accelerate use of endpoints the client ALREADY trusts via a separately-
 * verified manifest, never introduce one. A raw/legacy credential (no
 * envelope at all) or an envelope with no hints carries no scope signal -
 * [Unscoped] preserves exactly today's behavior (the caller's own explicit
 * target gateway), never a new gate on a path this slice does not touch
 * (B67.4's field-enrollment target-gateway selection, the manual-entry raw-
 * credential path).
 */
sealed class EntitlementScope {
    /** No signed scope signal - the caller's own explicit target is the only input, unchanged from pre-B67.6 behavior. */
    object Unscoped : EntitlementScope()

    /** A non-empty, signed [ActivationEnvelope.bootstrapEndpointHints] list - a candidate scope, not yet trust-checked against the manifest. */
    data class Hinted(val endpointIds: List<EndpointId>) : EntitlementScope()

    companion object {
        /** [ActivationEnvelope.bootstrapEndpointHints] is empty by construction whenever the issuer chose not to scope this credential. */
        fun fromEnvelopeHints(hints: List<EndpointId>): EntitlementScope =
            if (hints.isEmpty()) Unscoped else Hinted(hints)
    }
}

/** Deterministic, fail-closed outcome of resolving [EntitlementScope] against trusted/policy state. */
sealed class GatewayEligibilityResult {
    /** Never empty - see [EntitlementGatewayEligibility.resolve]. Order-preserving from the signed hint order. */
    data class Eligible(val gatewayIds: List<ProductionGatewayId>) : GatewayEligibilityResult()
    data class Denied(val reason: GatewayEligibilityDenialReason) : GatewayEligibilityResult()
}

enum class GatewayEligibilityDenialReason {
    /** [EntitlementScope.Hinted] but nothing is currently trusted at all (EndpointManifestRepository.trusted() == null). */
    NO_TRUSTED_MANIFEST,

    /** [EntitlementScope.Hinted] but none of the signed hints name an endpoint the trusted manifest currently carries. */
    NO_HINTED_ENDPOINT_TRUSTED,

    /** Hints are trusted-manifest-backed but none map to a known, product-supported gateway (ProductionGatewayCatalog membership - local/product policy). */
    NO_HINTED_ENDPOINT_SUPPORTED,
}

/**
 * Pure, deterministic decision logic - no I/O, no Android framework, no
 * network call. See this file's class docs for why [EntitlementScope.Hinted]
 * is intersected with BOTH the trusted manifest and
 * [net.pocvpn.client.vpn.config.ProductionGatewayCatalog] membership, never
 * either alone:
 *
 * - Manifest-only would let a signed hint's endpoint id become eligible even
 *   though this build/device has no such product gateway at all (there is
 *   no product policy layer between "in the manifest" and "connectable" -
 *   [net.pocvpn.client.vpn.config.ProductionGatewayCatalog] IS that layer,
 *   reused, never a second one).
 * - Catalog-only would let a hint name a real product gateway that the
 *   CURRENTLY trusted manifest has rolled back, expired, or never listed -
 *   exactly the state [net.pocvpn.client.reachability.EndpointManifestRepository]
 *   exists to prevent from being treated as current.
 *
 * A hint that fails either check is simply not eligible - never promoted,
 * never silently substituted with a different endpoint. [EntitlementScope
 * .Unscoped] is not filtered at all: it is the pre-B67.6 explicit-target
 * behavior, unchanged.
 */
object EntitlementGatewayEligibility {
    fun resolve(
        scope: EntitlementScope,
        trustedManifestEndpointIds: Set<EndpointId>,
        explicitRequestedGatewayId: ProductionGatewayId,
        gatewayIdForEndpointId: (EndpointId) -> ProductionGatewayId? = { net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byEndpointId(it) },
    ): GatewayEligibilityResult = when (scope) {
        is EntitlementScope.Unscoped -> GatewayEligibilityResult.Eligible(listOf(explicitRequestedGatewayId))
        is EntitlementScope.Hinted -> {
            if (trustedManifestEndpointIds.isEmpty()) {
                GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_TRUSTED_MANIFEST)
            } else {
                val trustedHints = scope.endpointIds.filter { it in trustedManifestEndpointIds }
                if (trustedHints.isEmpty()) {
                    GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_HINTED_ENDPOINT_TRUSTED)
                } else {
                    val known = trustedHints.mapNotNull(gatewayIdForEndpointId).distinct()
                    if (known.isEmpty()) {
                        GatewayEligibilityResult.Denied(GatewayEligibilityDenialReason.NO_HINTED_ENDPOINT_SUPPORTED)
                    } else {
                        GatewayEligibilityResult.Eligible(known)
                    }
                }
            }
        }
    }

    /**
     * B67.7 - the "existing trusted candidates + B67.6 eligibility
     * constraint -> eligible trusted candidates" step, applied to the
     * SAME manifest-derived [EndpointDescriptor] list
     * `AutoGatewaySelector.buildCandidates`/`buildCombinedAttempts` already
     * consume - never a second candidate source. This is a pure filter,
     * not a resolver: [eligibleGatewayIds] is whatever a PRIOR call to
     * [resolve] already decided (`null` for [EntitlementScope.Unscoped] or
     * "no active constraint" - see the caller's own docs for exactly when
     * that applies), so this function only narrows, never re-derives
     * eligibility from a hint.
     *
     * A `null` [eligibleGatewayIds] returns [endpoints] unchanged - the
     * pre-B67.7 candidate list, byte for byte. A non-null set keeps only
     * the entries that map to one of [eligibleGatewayIds] via
     * [net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byEndpointId]
     * (the SAME local/product-policy lookup [resolve] itself uses) -
     * **an endpoint that does not map to any product gateway at all (an
     * ingress/exit-only manifest entry - B67.6 eligibility has no defined
     * meaning for a non-gateway role) is left UNTOUCHED, never excluded by
     * a gateway-scoped constraint it was never about.** This keeps the
     * relayed/ingress candidate space (`MainViewModel.mergedIngressAwareEndpoints`)
     * completely outside this slice's scope, exactly as intended - B67.6
     * only ever produces a set of [ProductionGatewayId]s, and this filter
     * only ever acts on entries the catalog itself recognizes as one.
     */
    fun filterEligibleEndpoints(
        endpoints: List<EndpointDescriptor>,
        eligibleGatewayIds: Set<ProductionGatewayId>?,
        gatewayIdForEndpointId: (EndpointId) -> ProductionGatewayId? = { net.pocvpn.client.vpn.config.ProductionGatewayCatalog.byEndpointId(it) },
    ): List<EndpointDescriptor> {
        if (eligibleGatewayIds == null) return endpoints
        return endpoints.filter { endpoint ->
            val gatewayId = gatewayIdForEndpointId(endpoint.id)
            gatewayId == null || gatewayId in eligibleGatewayIds
        }
    }
}
