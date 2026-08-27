package net.pocvpn.client.transport

/**
 * How the user wants Smart Connect to pick a transport. Only AUTO is
 * functional in Phase 2A (single real transport, AmneziaWG) - FASTEST/STEALTH
 * are named for the future multi-transport scoring this architecture is
 * built for, not implemented yet. A developer/debug surface is enough for
 * now; no product UI is added for this in Phase 2A.
 */
sealed class UserTransportPreference {
    /** Let Smart Connect choose from whatever is AVAILABLE. */
    object Auto : UserTransportPreference()

    /** Future: prefer the lowest-latency AVAILABLE transport. Not implemented. */
    object Fastest : UserTransportPreference()

    /** Future: prefer the most obfuscated/restrictive-network-suitable AVAILABLE transport. Not implemented. */
    object Stealth : UserTransportPreference()

    /** User pinned a specific transport. Selection must reject it if it is not AVAILABLE. */
    data class Manual(val kind: TransportKind) : UserTransportPreference()
}
