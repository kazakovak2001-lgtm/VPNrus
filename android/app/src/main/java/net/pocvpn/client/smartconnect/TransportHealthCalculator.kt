package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportFailureCategory
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind

/**
 * B8L - the ONE place a real [TransportHealth] is computed for a given
 * transport kind, and the ONLY input it may read is history
 * ConnectionOutcomeStore already recorded (see ConnectionOutcome's own
 * docs) - never a fabricated or estimated value, matching TransportHealth's
 * own "only ever set from a genuinely measured probe" invariant. Pure/no
 * I/O - MainViewModel supplies [outcomes] fresh from
 * ConnectionOutcomeStore.recent() on every read, same no-caching pattern as
 * its other real-evidence reads (restrictionClass(), smartConnectDecision()).
 *
 * ConnectionOutcomeStore.recent() returns OLDEST FIRST (append order) - see
 * that interface's own docs - so the LAST matching entry is the most
 * recent attempt for [kind], never the first.
 */
object TransportHealthCalculator {

    /** Consecutive real failures for this kind at or above this count flip DEGRADED -> UNREACHABLE. */
    private const val UNREACHABLE_THRESHOLD = 2

    fun fromOutcomes(outcomes: List<ConnectionOutcome>, kind: TransportKind): TransportHealth {
        val forKind = outcomes.filter { it.transport == kind }
        val mostRecent = forKind.lastOrNull()
            ?: return TransportHealth(state = TransportHealthState.UNKNOWN)

        val consecutiveFailures = forKind.asReversed()
            .takeWhile { it.result == ConnectionOutcomeResult.FAILURE }
            .size

        val state = when {
            mostRecent.result == ConnectionOutcomeResult.SUCCESS -> TransportHealthState.HEALTHY
            consecutiveFailures >= UNREACHABLE_THRESHOLD -> TransportHealthState.UNREACHABLE
            else -> TransportHealthState.DEGRADED
        }

        return TransportHealth(
            state = state,
            lastProbeEpochMillis = mostRecent.timestampEpochMillis,
            // Only ever set from a genuinely measured SUCCESS - a FAILURE
            // never has a meaningful handshake duration to report.
            latencyMillis = if (mostRecent.result == ConnectionOutcomeResult.SUCCESS) mostRecent.handshakeDurationMs else null,
            failureCategory = if (mostRecent.result == ConnectionOutcomeResult.FAILURE) {
                mapFailureCategory(mostRecent.errorCategory)
            } else {
                TransportFailureCategory.NONE
            },
            consecutiveFailures = consecutiveFailures,
        )
    }

    private fun mapFailureCategory(category: ConnectionErrorCategory): TransportFailureCategory = when (category) {
        ConnectionErrorCategory.NONE -> TransportFailureCategory.NONE
        ConnectionErrorCategory.HANDSHAKE_TIMEOUT -> TransportFailureCategory.TIMEOUT
        ConnectionErrorCategory.RECONNECT_EXHAUSTED -> TransportFailureCategory.HANDSHAKE_FAILED
        ConnectionErrorCategory.BACKEND_START_FAILURE -> TransportFailureCategory.UNKNOWN
        ConnectionErrorCategory.OTHER -> TransportFailureCategory.UNKNOWN
    }
}
