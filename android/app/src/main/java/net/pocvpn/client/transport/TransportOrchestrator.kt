package net.pocvpn.client.transport

import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot

/**
 * B8I1 - RECONCILED: pure EXECUTOR only. Turns an ALREADY-MADE
 * TransportSelectionDecision into a real VpnTransport instance (or a typed
 * reason it can't) - it does NOT call SmartConnectDecisionEngine.decide()
 * itself any more (that was the "two decision authorities" risk: this class
 * previously re-derived its own transport choice from raw
 * NetworkProfile/preference/health, which could disagree with whatever the
 * real Smart Connect decision boundary - net.pocvpn.client.smartconnect
 * .SmartConnectCandidateSelector - had already decided for the SAME
 * connection attempt). The ONE decision authority is
 * SmartConnectCandidateSelector; this class only executes what it produced.
 *
 * Owns: candidate->instance resolution via the registry, and attempt
 * ordering for a future failover sequence. Does NOT own: user intent,
 * permission flow, connect/disconnect lifecycle, or reconnect - those
 * remain VpnController's responsibility. Not wired into VpnController yet -
 * the proven AWG connect path stays untouched until live Smart Connect is a
 * real gate.
 */
class TransportOrchestrator(private val registry: TransportRegistry) {

    sealed class Resolution {
        // B13 - [endpointId] defaults to the one real production endpoint so
        // every pre-B13 call site (every existing test, and
        // maybeFailoverToXray's own resolve() call before this slice) is
        // byte-for-byte unaffected. A caller that actually knows WHICH
        // candidate endpoint this attempt targets (MainViewModel.connect(),
        // which already has the real SmartConnectCandidateSelector-chosen
        // GatewayCandidate.id in hand) passes it explicitly instead of
        // relying on this default - see resolve()'s own docs.
        data class Resolved(
            val transport: VpnTransport,
            val kind: TransportKind,
            val endpointId: EndpointId = EndpointId(ProductionGateway.ID),
            // B16 - non-null exactly when this resolution came from an
            // automatic-gateway-selection candidate (AutoGatewaySelector's
            // own `GatewayAttemptCandidate.configSnapshot`, carried through
            // verbatim - see that class's own "Candidate identity" docs).
            // null (the default) for every manual-mode resolution, which
            // byte-for-byte preserves the pre-B16 behavior of
            // VpnController.doConnectAttempt() reading
            // gatewayConfigurationRepository.get() fresh. When non-null,
            // THIS is the exact, already-resolved config the attempt MUST
            // execute - VpnController never re-derives it from
            // SelectedGatewayStore/ProductionGatewayCatalog/
            // ClientTunnelIdentityStore once this Resolution exists (see
            // VpnController.resolveGatewayConfiguration's own docs).
            val gatewayConfigSnapshot: GatewayConfigSnapshot? = null,
            // B22 - non-null exactly when this resolution is a PRIVATE
            // gateway attempt (see MainViewModel.connectPrivate) - the
            // client keypair to use for THIS attempt instead of
            // VpnController's own default (managed-network) ClientKeyRepository.
            // null (the default) for every AUTO/MANUAL_MANAGED resolution,
            // byte-for-byte unaffected - see VpnController.buildTransportConfig's
            // own docs for exactly where this is consulted.
            val privateKeyRepository: ClientKeyRepository? = null,
        ) : Resolution()
        data class NotSelectable(val decision: TransportSelectionDecision) : Resolution()
    }

    /**
     * [decision] must already be the output of the ONE decision authority
     * (SmartConnectCandidateSelector, which itself delegates the transport
     * sub-decision to SmartConnectDecisionEngine) - this function never
     * second-guesses it. A decision naming a kind the registry can't
     * actually construct (e.g. stale/misconfigured registry) still fails
     * safe as NotSelectable, never silently substitutes a different kind.
     *
     * [endpointId] is the endpoint THIS attempt targets - see [Resolution.Resolved]'s
     * own docs for why it defaults to the one real production endpoint
     * rather than being invented here. [gatewayConfigSnapshot] threads an
     * already-resolved automatic-gateway-selection candidate's own pinned
     * config straight into the resulting [Resolution.Resolved] - see that
     * field's own docs. null (the default) for every manual-mode caller.
     */
    fun resolve(
        decision: TransportSelectionDecision,
        endpointId: EndpointId = EndpointId(ProductionGateway.ID),
        gatewayConfigSnapshot: GatewayConfigSnapshot? = null,
    ): Resolution {
        val selected = decision as? TransportSelectionDecision.SelectTransport
            ?: return Resolution.NotSelectable(decision)
        val transport = registry.createTransport(selected.kind)
            ?: return Resolution.NotSelectable(decision)
        return Resolution.Resolved(transport, selected.kind, endpointId, gatewayConfigSnapshot)
    }

    /** Deterministic ordering of currently-available transports, for a future failover sequence (not yet acted on). */
    fun candidateOrder(): List<TransportKind> = registry.available().map { it.kind }
}
