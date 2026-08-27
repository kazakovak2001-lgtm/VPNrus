package net.pocvpn.client.transport

/** Coarse runtime health for a transport. No background probing exists yet - see NetworkProfiler/probe(). */
enum class TransportHealthState {
    UNKNOWN,
    HEALTHY,
    DEGRADED,
    UNREACHABLE,
    NOT_IMPLEMENTED,
}

enum class TransportFailureCategory {
    NONE,
    NETWORK_UNAVAILABLE,
    HANDSHAKE_FAILED,
    TIMEOUT,
    UNKNOWN,
}

/**
 * A typed health snapshot for one transport. [latencyMillis] is only ever
 * set from a genuinely measured probe - never estimated or faked.
 */
data class TransportHealth(
    val state: TransportHealthState = TransportHealthState.UNKNOWN,
    val lastProbeEpochMillis: Long? = null,
    val latencyMillis: Long? = null,
    val failureCategory: TransportFailureCategory = TransportFailureCategory.NONE,
    val consecutiveFailures: Int = 0,
) {
    companion object {
        fun notImplemented(): TransportHealth = TransportHealth(state = TransportHealthState.NOT_IMPLEMENTED)
    }
}
