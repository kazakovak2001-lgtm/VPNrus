package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.config.GatewayConfiguration

/**
 * B8I1 - RECONCILED: SmartConnectCandidateSelector.decide() below is the
 * ONE production Smart Connect decision boundary (transport + gateway +
 * reason). It does NOT re-decide "which transport" independently - it
 * DELEGATES that sub-decision to the pre-existing
 * net.pocvpn.client.smartconnect.SmartConnectDecisionEngine (network-gating,
 * registry availability, user preference, health - already correct and
 * already tested; see SmartConnectDecisionEngineTest). B8I originally
 * re-implemented a second, parallel "pick AWG" decision here - that was the
 * duplicate-authority risk this reconciliation removes. There is exactly
 * ONE place that decides a transport kind now.
 *
 * net.pocvpn.client.transport.TransportOrchestrator is the EXECUTION side:
 * given a decision ALREADY made here, it turns a SelectTransport outcome
 * into a real VpnTransport instance - it no longer calls
 * SmartConnectDecisionEngine itself (see its own docs), so it can never
 * independently disagree with this boundary.
 *
 * net.pocvpn.client.vpn.policy.ClientRoutingPolicy/RoutingDecisionEngine are
 * a DIFFERENT axis entirely ("should THIS app/destination's traffic use the
 * VPN at all", per-flow) and are untouched by this reconciliation - they
 * are not part of transport/gateway selection.
 */
data class TransportCandidate(val kind: TransportKind)

/**
 * [id] is a stable, non-secret technical identifier (never the raw endpoint
 * host/IP) - the same value ConnectionOutcome.gatewayId uses, so historical
 * outcomes can be matched back to a candidate without re-exposing the
 * endpoint. [region] is user-facing display text only.
 */
data class GatewayCandidate(val id: String, val region: String)

data class ConnectionCandidate(val transport: TransportCandidate, val gateway: GatewayCandidate)

/**
 * Why THIS candidate was chosen. ONLY_AVAILABLE_CANDIDATE is the ONLY
 * reason real production traffic can produce today (exactly one transport x
 * one gateway exists - see productionGatewayCandidates below); the other
 * values are reserved for once real scoring/multiple candidates exist, so
 * this type doesn't need to change shape when that lands.
 */
enum class ConnectionScoreReason {
    ONLY_AVAILABLE_CANDIDATE,
    BEST_MEASURED_HANDSHAKE_HISTORY,
    USER_MANUAL_PREFERENCE,
}

data class ConnectionScore(val candidate: ConnectionCandidate, val reason: ConnectionScoreReason)

sealed class SmartConnectDecision {
    data class Selected(val score: ConnectionScore) : SmartConnectDecision()
    object NoCandidateAvailable : SmartConnectDecision()
}

/**
 * B8I1 - THE ONE Smart Connect decision authority. Composes:
 *  - CURRENT facts: [networkProfile] (NetworkProfiler's own output)
 *  - available transports: [registry]/[preference]/[health], resolved via
 *    the EXISTING SmartConnectDecisionEngine.decide() - reused, not
 *    reimplemented (see class docs)
 *  - available gateways: [gatewayCandidates] (today always 0 or 1 real one -
 *    see productionGatewayCandidates)
 *  - HISTORICAL evidence: [connectionHistory] - accepted now so this
 *    signature does not need to break again once real scoring lands, but
 *    genuinely UNUSED for a single-candidate decision today (see "keep
 *    selection trivial for now" - no fake ranking). Nothing in
 *    ConnectionOutcome is sensitive (see its own docs), so passing full
 *    history through this boundary is always safe.
 *
 * With exactly one real transport x one real gateway, the only truthful
 * reason is ONLY_AVAILABLE_CANDIDATE - this function never fabricates a
 * "best of several" story.
 */
object SmartConnectCandidateSelector {

    fun decide(
        networkProfile: NetworkProfile,
        gatewayCandidates: List<GatewayCandidate>,
        registry: TransportRegistry,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        health: Map<TransportKind, TransportHealth> = emptyMap(),
        connectionHistory: List<ConnectionOutcome> = emptyList(),
    ): SmartConnectDecision {
        if (gatewayCandidates.isEmpty()) return SmartConnectDecision.NoCandidateAvailable

        // The ONLY place a transport kind is decided - see class docs. This
        // already accounts for network usability/registry availability/user
        // preference/health, so none of that is re-checked or re-decided here.
        val transportDecision = SmartConnectDecisionEngine.decide(networkProfile, registry, preference, health)
        val kind = (transportDecision as? TransportSelectionDecision.SelectTransport)?.kind
            ?: return SmartConnectDecision.NoCandidateAvailable

        val gateway = gatewayCandidates.first()
        val candidate = ConnectionCandidate(TransportCandidate(kind), gateway)
        val reason = if (gatewayCandidates.size == 1) {
            ConnectionScoreReason.ONLY_AVAILABLE_CANDIDATE
        } else {
            // More than one real gateway does not exist in production yet -
            // deterministic first-pick, but this deliberately does NOT claim
            // ONLY_AVAILABLE_CANDIDATE when that would be false.
            ConnectionScoreReason.BEST_MEASURED_HANDSHAKE_HISTORY
        }
        return SmartConnectDecision.Selected(ConnectionScore(candidate, reason))
    }

    /**
     * The actual production gateway candidate list today: the one pinned
     * gateway (see B5's gateway/README.md - "Germany / Frankfurt"), reusing
     * the SAME [ProductionGateway.ID] ConnectionOutcome.gatewayId is
     * recorded under. Empty (not a fabricated candidate) whenever no
     * gateway is actually configured - mirrors GatewayConfiguration's own
     * Missing/Invalid fail-closed handling.
     */
    fun productionGatewayCandidates(gateway: GatewayConfiguration): List<GatewayCandidate> = when (gateway) {
        is GatewayConfiguration.Configured -> listOf(GatewayCandidate(id = ProductionGateway.ID, region = ProductionGateway.REGION_LABEL))
        is GatewayConfiguration.Missing, is GatewayConfiguration.Invalid -> emptyList()
    }
}

/** The one pinned production gateway's stable, non-secret identifiers (see B5/gateway/README.md). */
object ProductionGateway {
    const val ID = "frankfurt"
    const val REGION_LABEL = "Germany / Frankfurt"
}
