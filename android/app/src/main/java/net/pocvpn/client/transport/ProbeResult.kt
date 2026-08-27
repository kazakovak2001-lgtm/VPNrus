package net.pocvpn.client.transport

/**
 * Context for a future transport-reachability probe (e.g. "can we reach the
 * gateway over UDP/443 on this network right now?"). Deliberately minimal -
 * no probing is actually implemented in Phase 2A (see NetworkProfile FUTURE
 * fields); this exists only so VpnTransport.probe() has a typed input to
 * return NotSupported against, instead of an untyped no-op.
 */
data class ProbeContext(
    val timeoutMillis: Long = 3_000,
)

/** Result of asking a transport to probe reachability. Never fabricate Reachable. */
sealed class ProbeResult {
    data class Reachable(val latencyMillis: Long) : ProbeResult()
    object Unreachable : ProbeResult()

    /** The transport exists but does not implement probing yet (e.g. AmneziaWG in Phase 2A). */
    object Unsupported : ProbeResult()

    /** The transport itself is NOT_IMPLEMENTED (see TransportStatus). */
    object NotImplemented : ProbeResult()
}
