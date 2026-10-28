package net.pocvpn.client.diagnostics.fieldtest

/**
 * Why a bulk download produced no usable rate. Decided from the probe's exception TYPE
 * ([ProbeFailureKind]), status and byte counts - never from message text.
 */
enum class ThroughputNotMeasuredReason {
    /** The tunnel session left Connected / changed during the probes: nothing measured in it counts. */
    SESSION_INVALIDATED,
    DNS_FAILED,
    CONNECT_FAILED,
    TLS_FAILED,

    /** No response headers, or a response with no body byte. */
    NO_RESPONSE,

    /** The body stopped arriving after some bytes. */
    STALLED,

    /** The time budget ended before the body completed. */
    TIMEOUT,
    HTTP_ERROR,
}

/**
 * A transfer rate is only reported when a transfer was actually observed: a complete 2xx body in a
 * session that stayed valid. Everything else is "not measured" with a reason - a failed lookup or a
 * dead tunnel must never read as "0 kbit/s".
 */
sealed interface ThroughputVerdict {
    data class Measured(val rateKbps: Long, val transferMs: Long, val bytes: Long) : ThroughputVerdict

    data class NotMeasured(
        val reason: ThroughputNotMeasuredReason,
        val bytesRead: Long,
        val stalledAtBytes: Long?,
    ) : ThroughputVerdict
}

/** Pure. [sessionInvalidated] = the run's VPN-bound results were voided (session left Connected / changed). */
fun throughputVerdict(r: HttpProbeResult, sessionInvalidated: Boolean): ThroughputVerdict {
    fun not(reason: ThroughputNotMeasuredReason) = ThroughputVerdict.NotMeasured(reason, r.bytesRead, r.stalledAtBytes)
    return when {
        sessionInvalidated -> not(ThroughputNotMeasuredReason.SESSION_INVALIDATED)
        r.failureKind == ProbeFailureKind.UNKNOWN_HOST -> not(ThroughputNotMeasuredReason.DNS_FAILED)
        r.failureKind == ProbeFailureKind.TLS -> not(ThroughputNotMeasuredReason.TLS_FAILED)
        r.httpStatus == null && r.failureKind == ProbeFailureKind.TIMEOUT -> not(ThroughputNotMeasuredReason.NO_RESPONSE)
        r.httpStatus == null && r.failureKind != null -> not(ThroughputNotMeasuredReason.CONNECT_FAILED)
        r.httpStatus == null -> not(ThroughputNotMeasuredReason.NO_RESPONSE)
        r.httpStatus !in 200..299 -> not(ThroughputNotMeasuredReason.HTTP_ERROR)
        r.stalledAtBytes != null -> not(ThroughputNotMeasuredReason.STALLED)
        !r.ok || !r.bodyComplete -> not(ThroughputNotMeasuredReason.TIMEOUT)
        r.bytesRead <= 0 -> not(ThroughputNotMeasuredReason.NO_RESPONSE)
        else -> {
            // First-byte -> last-byte window; a probe without it (older result) falls back to the total time.
            val windowMs = (r.transferMs ?: r.elapsedMs).coerceAtLeast(1)
            ThroughputVerdict.Measured(rateKbps = r.bytesRead * 8 / windowMs, transferMs = windowMs, bytes = r.bytesRead)
        }
    }
}
