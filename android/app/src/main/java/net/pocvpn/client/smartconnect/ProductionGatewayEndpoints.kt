package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayDescriptor

/**
 * B16 - builds the [EndpointDescriptor] the existing reachability pipeline
 * (ReachabilityEngine -> PathCandidateBuilder -> PathScorer, see
 * PROJECT_ARCHITECTURE.md's fixed pipeline order) needs for one real
 * production gateway, straight from [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]
 * rather than the Signed Offline Bootstrap manifest.
 *
 * Deliberately SEPARATE from that manifest (see EmbeddedBootstrapManifest's
 * own docs): the embedded/production manifest only ever names the single
 * "frankfurt" endpoint today, and extending it to also name Stockholm would
 * require re-running the offline manifest-signing key ceremony - explicitly
 * out of scope for this slice ("do not change Signed Offline Bootstrap key
 * ceremony"). ProductionGatewayCatalog is already this codebase's own
 * trusted, hardcoded, code-reviewed source of gateway facts (the real AWG
 * data-plane connection details are sourced from it exactly the same way,
 * see SelectedProductionGatewaySource) - reusing it here to build a
 * same-shaped EndpointDescriptor lets automatic gateway selection reuse the
 * EXISTING, UNMODIFIED PathCandidateBuilder/PathScorer/ReachabilityEngine
 * pipeline for both real gateways, rather than inventing a second/parallel
 * scoring path (task requirement: "Do not create a parallel scoring
 * system").
 *
 * [xrayAvailable]/[xrayTlsAvailable] must reflect the SAME per-endpoint
 * availability MainViewModel.isXrayAvailableFor/isXrayTlsAvailableFor
 * already compute (a real, persisted profile for THIS endpoint) - never a
 * hardcoded true, so an unprovisioned transport is correctly absent from
 * [EndpointDescriptor.transports] and therefore ineligible at
 * PathCandidateBuilder.buildDirect (which requires `gateway.supports(transport)`).
 */
object ProductionGatewayEndpoints {

    /**
     * The real, already-deployed listener ports for the REALITY/TLS Xray
     * inbounds both gateways' nginx/Xray config actually use (see
     * docs/ROADMAP.md's Gateway Pool row: "port 2053" / "port 2083") - a
     * fixed infrastructure fact, not reachability evidence, and identical to
     * what this codebase already documents elsewhere.
     */
    private const val REALITY_PORT = 2053
    private const val TLS_PORT = 2083

    fun descriptorFor(
        gateway: ProductionGatewayDescriptor,
        xrayAvailable: Boolean,
        xrayTlsAvailable: Boolean,
    ): EndpointDescriptor {
        val transports = buildList {
            add(EndpointTransportBinding(TransportKind.AMNEZIA_WG, gateway.awg.endpointHost, gateway.awg.endpointPort))
            if (xrayAvailable) add(EndpointTransportBinding(TransportKind.XRAY_REALITY, gateway.awg.endpointHost, REALITY_PORT))
            if (xrayTlsAvailable) add(EndpointTransportBinding(TransportKind.TLS_TCP, gateway.awg.endpointHost, TLS_PORT))
        }
        return EndpointDescriptor(
            id = gateway.endpointId,
            roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
            region = "${gateway.displayCountry} / ${gateway.displayCity}",
            provider = gateway.provider,
            transports = transports,
        )
    }
}
