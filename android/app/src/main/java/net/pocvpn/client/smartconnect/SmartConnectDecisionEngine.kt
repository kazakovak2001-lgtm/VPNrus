package net.pocvpn.client.smartconnect

import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportRegistry
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.transport.UserTransportPreference

/**
 * Pure decision engine: given the current network and what's actually
 * available, decide which transport (if any) should be used - never
 * connects to anything itself. Deterministic - no random fallback ordering.
 */
object SmartConnectDecisionEngine {

    /**
     * Fixed, deterministic priority when more than one transport is
     * AVAILABLE. Only AMNEZIA_WG is real today. `internal` (not private) -
     * TransportScorer.rank() (B8N) reuses THIS SAME list for its own
     * tie-break, rather than an independent copy that could silently drift
     * out of sync with the actual decision authority's own order.
     */
    internal val PREFERRED_ORDER = listOf(
        TransportKind.AMNEZIA_WG,
        TransportKind.QUIC,
        TransportKind.XRAY_REALITY,
        TransportKind.TLS_TCP,
    )

    fun decide(
        networkProfile: NetworkProfile,
        registry: TransportRegistry,
        preference: UserTransportPreference = UserTransportPreference.Auto,
        health: Map<TransportKind, TransportHealth> = emptyMap(),
    ): TransportSelectionDecision {
        if (!networkProfile.isUsable) return TransportSelectionDecision.NetworkUnavailable

        return when (preference) {
            is UserTransportPreference.Manual -> decideManual(registry, preference.kind)
            // FASTEST/STEALTH have no scoring signal to act on yet (single real
            // transport) - deliberately falls through to the same deterministic
            // logic as AUTO rather than fabricating a latency/stealth score.
            UserTransportPreference.Auto,
            UserTransportPreference.Fastest,
            UserTransportPreference.Stealth,
            -> decideAuto(registry)
        }
    }

    private fun decideManual(registry: TransportRegistry, kind: TransportKind): TransportSelectionDecision {
        val descriptor = registry.descriptorFor(kind)
        return if (descriptor?.status == TransportStatus.AVAILABLE) {
            TransportSelectionDecision.SelectTransport(kind)
        } else {
            TransportSelectionDecision.UserPolicyBlocked
        }
    }

    private fun decideAuto(registry: TransportRegistry): TransportSelectionDecision {
        val available = registry.available()
        if (available.isEmpty()) return TransportSelectionDecision.NoTransportAvailable
        val availableKinds = available.map { it.kind }.toSet()
        val chosen = PREFERRED_ORDER.firstOrNull { it in availableKinds } ?: available.first().kind
        return TransportSelectionDecision.SelectTransport(chosen)
    }
}
