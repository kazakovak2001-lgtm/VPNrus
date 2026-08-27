package net.pocvpn.client.transport

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.smartconnect.SmartConnectDecisionEngine
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.vpn.VpnTransport

/**
 * Resolves a Smart Connect decision into an actual transport instance (or a
 * typed reason it can't). Owns: candidate selection via the registry,
 * availability checks, and attempt ordering for a future failover sequence.
 *
 * Does NOT own: user intent, permission flow, connect/disconnect lifecycle,
 * or reconnect - those remain VpnController's responsibility. Not wired
 * into VpnController in Phase 2A - see Phase 2A report for why (the proven
 * AWG connect path stays untouched until live Smart Connect is a real gate).
 */
class TransportOrchestrator(private val registry: TransportRegistry) {

    sealed class Resolution {
        data class Resolved(val transport: VpnTransport, val kind: TransportKind) : Resolution()
        data class NotSelectable(val decision: TransportSelectionDecision) : Resolution()
    }

    fun resolve(
        networkProfile: NetworkProfile,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        health: Map<TransportKind, TransportHealth> = emptyMap(),
    ): Resolution {
        val decision = SmartConnectDecisionEngine.decide(networkProfile, registry, preference, health)
        val selected = decision as? TransportSelectionDecision.SelectTransport
            ?: return Resolution.NotSelectable(decision)
        val transport = registry.createTransport(selected.kind)
            ?: return Resolution.NotSelectable(decision)
        return Resolution.Resolved(transport, selected.kind)
    }

    /** Deterministic ordering of currently-available transports, for a future failover sequence (not yet acted on). */
    fun candidateOrder(): List<TransportKind> = registry.available().map { it.kind }
}
