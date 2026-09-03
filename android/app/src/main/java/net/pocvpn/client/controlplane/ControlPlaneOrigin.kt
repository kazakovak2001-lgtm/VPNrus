package net.pocvpn.client.controlplane

import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId

/**
 * B30 - one candidate network path to a gateway's own control-plane (the
 * same HTTPS edge activation/xray-profile/ingress-profile already target -
 * see [ProvisioningClient]). Deliberately carries no path/credential - only
 * [gatewayId] (a closed, non-secret enum) and [host] (needed to actually
 * open the connection, but NEVER logged/recorded into diagnostics - see
 * [net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder]'s own
 * "no origin hostname/IP" rule; callers tag diagnostic events with
 * [gatewayId] + an origin INDEX instead, never this field).
 */
data class ControlPlaneOrigin(val gatewayId: ProductionGatewayId, val host: String)

/**
 * B30 (task 1) - THE ONE place a [ControlPlaneOrigin] list is built, always
 * from [ProductionGatewayCatalog] - the same compiled, trusted-at-build-time
 * configuration every other gateway-identity fact in this codebase already
 * comes from (see that object's own docs: "the real, hardcoded set of
 * production gateways this app can connect a device to"). Never accepts a
 * caller-supplied host/URL - this is precisely the fail-closed guarantee
 * task requirement 2 ("never accept arbitrary user-supplied activation URLs
 * in Auto mode") depends on structurally, not by convention: there is no
 * parameter here through which one could be smuggled in.
 *
 * Today's compiled catalog carries exactly ONE physical origin per gateway
 * (see ProductionGatewayCatalog's own docs on Germany/Stockholm) - so this
 * always returns a single-element list per gateway right now. The list
 * shape itself (rather than a bare host string) is what makes
 * [TrustedOriginRequestExecutor] genuinely N-origin-capable the moment ops
 * adds a second trusted physical or CDN-fronted origin for one gateway
 * (mirroring B27's CDN-fronted ingress binding, extended to the
 * control-plane) - no caller of this function needs to change when that
 * happens, only this one builder.
 */
object ControlPlaneOriginSetBuilder {
    fun forGateway(gatewayId: ProductionGatewayId): List<ControlPlaneOrigin> =
        listOf(ControlPlaneOrigin(gatewayId, ProductionGatewayCatalog.byId(gatewayId).awg.endpointHost))
}
