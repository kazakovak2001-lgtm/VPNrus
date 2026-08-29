package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind

/**
 * B8I - technical connection-attempt metadata only. See ConnectionOutcomeStore's
 * own docs for the privacy invariant this type exists to enforce: no IP
 * addresses, no destinations/DNS/browsing data, no credentials or key
 * material - just enough to answer "did AWG/Frankfurt tend to work, and how
 * fast" for a future Smart Connect scoring pass. Every field is either an
 * enum, a duration, or a timestamp.
 */
enum class ConnectionOutcomeResult { SUCCESS, FAILURE }

/**
 * Coarse, non-identifying failure buckets - mirrors the REAL VpnError cases
 * VpnController already raises from actual evidence (see VpnController.kt's
 * own doConnectAttempt/reconnectLoop), never a guess. NONE is the only
 * category a SUCCESS outcome ever carries.
 */
enum class ConnectionErrorCategory {
    NONE,
    HANDSHAKE_TIMEOUT,
    RECONNECT_EXHAUSTED,
    BACKEND_START_FAILURE,
    OTHER,
}

/**
 * One real, evidence-based connection attempt outcome. [handshakeDurationMs]
 * is the wall-clock time from the attempt's own start until this outcome was
 * determined (success OR failure) - never estimated, never backfilled for an
 * attempt that never happened. [gatewayId]/[transport] are stable technical
 * identifiers (see ConnectionCandidate), never a raw endpoint/IP.
 */
data class ConnectionOutcome(
    val transport: TransportKind,
    val gatewayId: String,
    val result: ConnectionOutcomeResult,
    val handshakeDurationMs: Long?,
    val errorCategory: ConnectionErrorCategory,
    val timestampEpochMillis: Long,
)
