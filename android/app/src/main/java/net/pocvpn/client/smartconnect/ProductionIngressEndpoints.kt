package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.withIngressKind
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog

/**
 * B31 - the real, hardcoded relay-topology fact [AutoGatewaySelector.buildRelayedCandidates]
 * needs to construct a genuine PathCandidate.Relayed (CHAIN_DIRECT) for the
 * one production INGRESS deployed so far: Stockholm's own B25/B31 ingress
 * role (client-facing VLESS+REALITY on port 2093, relaying to the pinned
 * Germany/Frankfurt EXIT) - see PROJECT_ARCHITECTURE.md's B25/B31 sections
 * and docs/ROADMAP.md's Gateway Pool row for the deployed facts this
 * mirrors.
 *
 * Deliberately mirrors [ProductionGatewayEndpoints]' own established pattern
 * (a hardcoded, code-reviewed catalog -> EndpointDescriptor bridge) rather
 * than extending EmbeddedBootstrapManifest/the signed production manifest:
 * that manifest's own docs already establish that naming a new endpoint
 * there requires re-running the offline manifest-signing key ceremony (an
 * operator-only, out-of-repository action - see
 * docs/B12_MANIFEST_KEY_CEREMONY.md) - the exact same reasoning
 * [ProductionGatewayEndpoints] itself already gives for why Stockholm's own
 * GATEWAY/EXIT facts live here and not in that manifest. The manifest's own
 * wire format (ManifestCanonicalizer) and [net.pocvpn.client.reachability.PathCandidateBuilder]
 * are both already fully generic over INGRESS/relayTo/IngressKind - nothing
 * about either needed to change for this object to exist.
 *
 * A SEPARATE [EndpointId] from Stockholm's own ordinary GATEWAY/EXIT
 * descriptor ([ProductionGatewayEndpoints.descriptorFor] over
 * [ProductionGatewayCatalog.STOCKHOLM]) - the two are deliberately distinct
 * deployments/roles on the same physical host. They could not be merged
 * into one descriptor even if that were desirable: EndpointDescriptor
 * forbids two bindings of the same TransportKind on one descriptor, and the
 * ingress's own REALITY port genuinely differs from Stockholm's ordinary
 * REALITY port (2093 vs 2053). [STOCKHOLM_INGRESS_ID]'s value is the SAME id
 * the deployed ingress's own control plane already uses as its
 * endpoint_id/`ingress_endpoint_id` (see relay_probe_token's own
 * historyPathId contract, gateway/api/ingress_config.py) - never invented
 * independently here.
 *
 * Relays to [ProductionGatewayCatalog.GERMANY]'s own `endpointId`
 * ("frankfurt") - the SAME id [ProductionGatewayEndpoints.descriptorFor]
 * already uses for Germany's own EXIT descriptor, so
 * [net.pocvpn.client.reachability.PathCandidateBuilder.buildRelayed]'s own
 * `ingress.relayTo != exit.id` check is satisfied against that EXACT
 * descriptor - callers must resolve Germany's descriptor via
 * [ProductionGatewayEndpoints.descriptorFor], never a second/independent one.
 *
 * **Not yet consumed by the live connect path** - same deliberate deferral
 * [AutoGatewaySelector.buildRelayedCandidates] itself already documents.
 * This object only makes the real ingress topology DATA available to that
 * already-generic pipeline; promoting it into `MainViewModel.connectAuto()`/
 * `VpnController` execution is a separate decision (now that real
 * infrastructure and a real end-to-end server-side proof exist, unlike when
 * that deferral was first written) - out of scope for this narrow change.
 *
 * Carries only public routing/topology facts - no activation credential, no
 * VLESS client UUID, no private key, no per-device tunnel identity, no relay
 * or HMAC secret. Those remain exactly where they already live (the
 * per-device encrypted profile stores), never duplicated here - same
 * discipline [EndpointDescriptor]'s own docs already require of every
 * endpoint source.
 */
object ProductionIngressEndpoints {

    /**
     * The deployed ingress's own stable endpoint id - see this object's own
     * docs for why this exact string, and why it must stay distinct from
     * [ProductionGatewayCatalog.STOCKHOLM]'s `endpointId` ("stockholm").
     */
    val STOCKHOLM_INGRESS_ID: EndpointId = EndpointId("stockholm-ingress-1")

    /**
     * The real, already-deployed client-facing VLESS+REALITY listener port
     * for Stockholm's B25/B31 ingress role (see gateway/config/ingress.env's
     * own NOVA_INGRESS_SERVER_PORT) - deliberately distinct from Stockholm's
     * ordinary REALITY port ([ProductionGatewayEndpoints]'s own 2053).
     */
    private const val INGRESS_REALITY_PORT = 2093

    /**
     * Stockholm's INGRESS role: a DIRECT_IP ingress, client-facing
     * VLESS+REALITY only (no TLS ingress listener is deployed), relaying to
     * [ProductionGatewayCatalog.GERMANY]. Reuses
     * [ProductionGatewayCatalog.STOCKHOLM]'s own host/region/provider facts
     * rather than re-stating the IP a second time.
     */
    val STOCKHOLM: EndpointDescriptor = EndpointDescriptor(
        id = STOCKHOLM_INGRESS_ID,
        roles = setOf(EndpointRole.INGRESS),
        region = "${ProductionGatewayCatalog.STOCKHOLM.displayCountry} / ${ProductionGatewayCatalog.STOCKHOLM.displayCity}",
        provider = ProductionGatewayCatalog.STOCKHOLM.provider,
        transports = listOf(
            EndpointTransportBinding(
                TransportKind.XRAY_REALITY,
                ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
                INGRESS_REALITY_PORT,
            ).withIngressKind(IngressKind.DIRECT_IP),
        ),
        relayTo = ProductionGatewayCatalog.GERMANY.endpointId,
    )

    /** Every deployed ingress endpoint - today, just Stockholm's. */
    val all: List<EndpointDescriptor> = listOf(STOCKHOLM)
}
