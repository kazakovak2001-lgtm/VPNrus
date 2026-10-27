package net.pocvpn.client.vpn.traffic

import java.util.Locale
import net.pocvpn.client.transport.TransportStats

/** One reading of the live speed indicator. */
sealed class TrafficRate {
    /** The active transport exposes no usable tunnel counters right now (never shown as zero). */
    object Unavailable : TrafficRate()

    /** Counters are readable but no rate exists yet (first sample, or the baseline was just reset). */
    object Measuring : TrafficRate()

    /** Smoothed tunnel throughput in bytes per second; 0 is genuine idle, never a placeholder. */
    data class Rate(val downloadBytesPerSecond: Long, val uploadBytesPerSecond: Long) : TrafficRate()
}

/**
 * Live speed indicator - turns the active session's CUMULATIVE tunnel byte
 * counters ([TransportStats.Counters], the same [net.pocvpn.client.vpn.VpnTransport.dataPlaneCounters]
 * the post-connect data-plane check reads) into a smoothed rate from counter
 * deltas over monotonic elapsed time. Pure and single-threaded: one meter per
 * Connected period, fed by [VpnTrafficIndicator] only.
 *
 * Never invents a rate: the first sample, a counter going backwards (reset
 * or new session), a non-advancing clock or a gap longer than
 * [maxIntervalMillis] only (re)set the baseline and report [TrafficRate.Measuring];
 * non-counter stats report [TrafficRate.Unavailable]. Smoothing is an EMA with
 * weight [smoothing] on the newest interval, and two idle intervals in a row
 * snap a direction to 0 so a stopped download does not trail off for seconds.
 */
class TrafficRateMeter(
    private val smoothing: Double = 0.5,
    private val maxIntervalMillis: Long = 10_000,
) {
    private var baseline: Sample? = null
    private val down = Direction()
    private val up = Direction()

    fun update(elapsedRealtimeMillis: Long, stats: TransportStats): TrafficRate {
        val counters = stats as? TransportStats.Counters
        if (counters == null || counters.bytesReceived < 0 || counters.bytesSent < 0) {
            reset()
            return TrafficRate.Unavailable
        }
        val sample = Sample(elapsedRealtimeMillis, counters.bytesReceived, counters.bytesSent)
        val previous = baseline
        val elapsed = previous?.let { sample.atMillis - it.atMillis }
        if (previous == null || elapsed == null || elapsed > maxIntervalMillis ||
            sample.rx < previous.rx || sample.tx < previous.tx
        ) {
            reset()
            baseline = sample
            return TrafficRate.Measuring
        }
        // Same or earlier timestamp: no interval to divide by - keep the baseline.
        if (elapsed <= 0) return current()
        baseline = sample
        down.add((sample.rx - previous.rx) * 1000.0 / elapsed, smoothing)
        up.add((sample.tx - previous.tx) * 1000.0 / elapsed, smoothing)
        return current()
    }

    private fun current(): TrafficRate {
        val d = down.smoothed ?: return TrafficRate.Measuring
        val u = up.smoothed ?: return TrafficRate.Measuring
        return TrafficRate.Rate(Math.round(d), Math.round(u))
    }

    private fun reset() {
        baseline = null
        down.clear()
        up.clear()
    }

    private data class Sample(val atMillis: Long, val rx: Long, val tx: Long)

    private class Direction {
        var smoothed: Double? = null
            private set
        private var idleIntervals = 0

        fun add(instant: Double, weight: Double) {
            idleIntervals = if (instant == 0.0) idleIntervals + 1 else 0
            val prev = smoothed
            smoothed = when {
                idleIntervals >= 2 || prev == null -> instant
                else -> weight * instant + (1 - weight) * prev
            }
        }

        fun clear() {
            smoothed = null
            idleIntervals = 0
        }
    }
}

/** Decimal units: 1 kB/s = 1000 B/s, 1 MB/s = 1000 kB/s (same base as Android's own Formatter since API 26). */
object TrafficRateFormat {
    fun speed(bytesPerSecond: Long): String {
        val b = bytesPerSecond.coerceAtLeast(0)
        return when {
            b < 1_000 -> "$b B/s"
            b < 999_500 -> scaled(b / 1e3, "kB/s")
            b < 999_500_000 -> scaled(b / 1e6, "MB/s")
            else -> scaled(b / 1e9, "GB/s")
        }
    }

    fun line(rate: TrafficRate.Rate): String = "↓ ${speed(rate.downloadBytesPerSecond)}  ↑ ${speed(rate.uploadBytesPerSecond)}"

    private fun scaled(value: Double, unit: String): String =
        String.format(Locale.ROOT, if (value < 9.95) "%.1f %s" else "%.0f %s", value, unit)
}
