package net.pocvpn.client.controlplane

import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B30 review fix (blocker 2's own "verify all profile retrieval endpoints
 * that are supposed to use this generic executor are actually wired through
 * it, not only instrumented") - the SAME [TrustedOriginRequestExecutor]/
 * [ControlPlaneOriginSetBuilder] [net.pocvpn.client.controlplane.ActivationResilienceCoordinator]
 * uses, generalized for any GATEWAY-SCOPED profile fetch (Xray/REALITY,
 * Xray/TLS) whose per-attempt result is already reducible to a
 * [ControlPlaneFailureReason]? via [classify]. `fetch` is invoked once per
 * origin in [origins] (bounded, typed, no infinite retry - see the
 * executor's own docs); [lastResult] semantics mirror
 * [ActivationResilienceCoordinator.Outcome.AllOriginsExhausted]'s own -
 * on total exhaustion the LAST origin's own raw result is returned, never a
 * synthesized value, so a caller's existing per-status outcome mapping stays
 * byte-for-byte reusable.
 *
 * Deliberately NOT used for ingress-profile fetch
 * ([net.pocvpn.client.relay.IngressProfileProvisioner]): an ingress endpoint
 * is [net.pocvpn.client.reachability.EndpointId]-scoped, not
 * [ProductionGatewayId]-scoped (it need not be one of the two production
 * gateways at all - see [ControlPlaneOrigin]'s own docs) - forcing it into
 * this gateway-identified origin model would misrepresent what's actually
 * trusted. That provisioner stays diagnostics-instrumented around its own
 * single, already-pinned `ingressBinding.host` call, which is the ONLY
 * origin that could ever be correct for that specific ingress.
 */
fun <R> fetchThroughTrustedOrigins(
    gatewayId: ProductionGatewayId,
    diagnosticsRecorder: SupportDiagnosticsRecorder?,
    classify: (R) -> ControlPlaneFailureReason?,
    origins: List<ControlPlaneOrigin> = ControlPlaneOriginSetBuilder.forGateway(gatewayId),
    fetch: (ControlPlaneOrigin) -> R,
): R {
    diagnosticsRecorder?.recordProfileFetchStarted()
    var lastResult: R? = null
    val originIndexOf = origins.withIndex().associate { (i, o) -> o to i }
    val executed = TrustedOriginRequestExecutor.execute(
        origins = origins,
        onAttemptResult = { origin, reason ->
            if (reason == null) {
                diagnosticsRecorder?.recordControlOriginSucceeded(gatewayId, originIndexOf.getValue(origin))
            } else {
                diagnosticsRecorder?.recordControlOriginFailed(gatewayId, originIndexOf.getValue(origin), reason)
            }
        },
        callPerOrigin = { origin ->
            val result = fetch(origin)
            lastResult = result
            val reason = classify(result)
            if (reason == null) {
                TrustedOriginRequestExecutor.OriginCallResult.Success(result)
            } else {
                TrustedOriginRequestExecutor.OriginCallResult.Failure(reason)
            }
        },
    )
    return when (executed) {
        is TrustedOriginRequestExecutor.ExecutionResult.Success -> {
            diagnosticsRecorder?.recordProfileFetchSucceeded()
            executed.value
        }
        is TrustedOriginRequestExecutor.ExecutionResult.Exhausted -> {
            diagnosticsRecorder?.recordProfileFetchFailed(executed.failures.last().reason)
            // origins is non-empty (TrustedOriginRequestExecutor.execute
            // requires it), so callPerOrigin ran at least once - lastResult
            // is always set by the time Exhausted is reached.
            lastResult!!
        }
    }
}
