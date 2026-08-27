package net.pocvpn.client.transport

/**
 * Non-secret traffic statistics for a transport. NEVER include key material,
 * endpoint credentials, or full config here - see DiagnosticsSnapshot for
 * the same invariant on the existing diagnostics model.
 */
sealed class TransportStats {
    data class Counters(
        val bytesReceived: Long,
        val bytesSent: Long,
        val lastHandshakeEpochMillis: Long?,
    ) : TransportStats()

    /** The transport exists but does not expose stats yet (e.g. AmneziaWG in Phase 2A - see B8A limitation). */
    object Unsupported : TransportStats()

    /** The transport itself is NOT_IMPLEMENTED. */
    object NotImplemented : TransportStats()

    /** Stats were expected but are not available right now (e.g. not connected). */
    object Unavailable : TransportStats()
}
