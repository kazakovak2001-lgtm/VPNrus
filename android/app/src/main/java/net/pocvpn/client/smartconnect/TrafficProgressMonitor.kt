package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportStats

/**
 * B-WL7 - one cumulative counter reading from a live session, taken from the
 * transport's existing non-secret [TransportStats.Counters] (see
 * [fromCounters]). [elapsedMillis] is monotonic time since the session was
 * established - never wall-clock, so clock changes cannot fake progress.
 */
data class TrafficProgressSample(
    val elapsedMillis: Long,
    val bytesReceived: Long,
    val bytesSent: Long,
) {
    companion object {
        /** Null for every non-counter [TransportStats] (Unsupported/Unavailable/NotImplemented) - no progress can be inferred from them. */
        fun fromCounters(stats: TransportStats, elapsedMillis: Long): TrafficProgressSample? =
            (stats as? TransportStats.Counters)?.let { TrafficProgressSample(elapsedMillis, it.bytesReceived, it.bytesSent) }
    }
}

/**
 * Bounded windows, not byte thresholds. [verificationWindowMillis]: how long
 * receive progress must keep advancing before a fresh session counts as
 * verified. [stallWindowMillis]: how long the peer may stay silent WHILE we
 * keep sending before the session counts as stalled.
 */
data class TrafficProgressPolicy(
    val verificationWindowMillis: Long = DEFAULT_VERIFICATION_WINDOW_MILLIS,
    val stallWindowMillis: Long = DEFAULT_STALL_WINDOW_MILLIS,
) {
    init {
        require(verificationWindowMillis > 0 && stallWindowMillis > 0) { "windows must be positive" }
    }

    companion object {
        const val DEFAULT_VERIFICATION_WINDOW_MILLIS: Long = 10_000L
        const val DEFAULT_STALL_WINDOW_MILLIS: Long = 20_000L
    }
}

enum class TrafficProgressVerdict {
    /** Not enough time/samples yet to decide - never promoted to healthy by default. */
    VERIFYING,
    /** Receive counter advanced repeatedly across the verification window. */
    VERIFIED,
    /** We sent, the peer never sent anything back within the stall window. */
    NO_PAYLOAD,
    /** Some payload arrived, then nothing more for a full stall window while we kept sending (early-drop shape). */
    STALLED_AFTER_INITIAL_PAYLOAD,
    /** Neither side sent anything - an idle session, not evidence of a fault. */
    IDLE,
    /** Counters went backwards or samples are unusable - no conclusion. */
    UNAVAILABLE,
}

/**
 * B-WL7 - pure post-connect traffic-progress judgement: "TCP connect != VPN
 * working, TLS handshake != VPN working, Xray process running != VPN
 * working". Decides only from observed counter progress over bounded windows.
 *
 * Idle is distinguished from stalled: silence counts as a stall only when
 * OUR side kept sending during the stall window (outbound demand with no
 * inbound answer). No magic byte count appears anywhere - an early drop at
 * any size looks the same here.
 *
 * Not yet wired into VpnController's live session loop (that wiring needs an
 * Android build to verify - see docs/ROADMAP.md B-WL7); VpnController's
 * existing handshake/remote-confirmation gates remain the live authority.
 */
object TrafficProgressMonitor {

    fun evaluate(samples: List<TrafficProgressSample>, policy: TrafficProgressPolicy = TrafficProgressPolicy()): TrafficProgressVerdict {
        if (samples.isEmpty()) return TrafficProgressVerdict.VERIFYING
        val ordered = samples.sortedBy { it.elapsedMillis }
        if (ordered.zipWithNext().any { (a, b) -> b.bytesReceived < a.bytesReceived || b.bytesSent < a.bytesSent }) {
            return TrafficProgressVerdict.UNAVAILABLE
        }
        val first = ordered.first()
        val last = ordered.last()
        // Counters are cumulative since session start.
        val totalReceived = last.bytesReceived

        // Last moment the peer's counter moved, and how much we sent since then.
        val lastRxAdvance = ordered.zipWithNext().lastOrNull { (a, b) -> b.bytesReceived > a.bytesReceived }?.second
        val silentSince = lastRxAdvance ?: first
        val silentForMillis = last.elapsedMillis - silentSince.elapsedMillis
        val sentDuringSilence = last.bytesSent > silentSince.bytesSent

        if (silentForMillis >= policy.stallWindowMillis && sentDuringSilence) {
            return if (totalReceived > 0) TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD else TrafficProgressVerdict.NO_PAYLOAD
        }

        val rxAdvances = ordered.zipWithNext().filter { (a, b) -> b.bytesReceived > a.bytesReceived }
        if (rxAdvances.size >= 2 && last.elapsedMillis - first.elapsedMillis >= policy.verificationWindowMillis && silentForMillis < policy.stallWindowMillis) {
            return TrafficProgressVerdict.VERIFIED
        }

        // Long silence with no outbound demand either: idle, never a fault.
        if (silentForMillis >= policy.stallWindowMillis) return TrafficProgressVerdict.IDLE
        return TrafficProgressVerdict.VERIFYING
    }

    /** Maps a verdict onto the B-WL1 observation vocabulary; VERIFYING/IDLE/UNAVAILABLE carry no progress claim. */
    fun toProgressOutcome(verdict: TrafficProgressVerdict): TrafficProgressOutcome = when (verdict) {
        TrafficProgressVerdict.VERIFIED -> TrafficProgressOutcome.SUSTAINED
        TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD -> TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD
        TrafficProgressVerdict.NO_PAYLOAD -> TrafficProgressOutcome.NO_PAYLOAD
        TrafficProgressVerdict.VERIFYING, TrafficProgressVerdict.IDLE, TrafficProgressVerdict.UNAVAILABLE -> TrafficProgressOutcome.NOT_OBSERVED
    }

    /** B-WL7 runtime health: only a real stall/no-payload verdict is UNHEALTHY; everything else is not (yet) evidence of failure. */
    fun isUnhealthy(verdict: TrafficProgressVerdict): Boolean =
        verdict == TrafficProgressVerdict.STALLED_AFTER_INITIAL_PAYLOAD || verdict == TrafficProgressVerdict.NO_PAYLOAD
}
