package net.pocvpn.client.ui

import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.traffic.TrafficRate

/**
 * Home dashboard - measures CONTINUOUS PROTECTED time on a monotonic clock.
 * Pure and single-threaded (fed by MainViewModel from the one sessionHealth
 * flow); the UI only subtracts the start from "now", it never owns the start.
 *
 * - The timer starts when health becomes protected after having been seen
 *   NOT protected (so we witnessed the transition).
 * - It resets to null the moment health leaves protected (reconnecting,
 *   verifying, failed, idle) - a reconnect is a new tunnel, so a stale
 *   duration would be misleading.
 * - If the very first observation is already protected the real start is
 *   unknown, so no duration is reported until the next genuine transition.
 * - If the clock cannot be read the start is unknown (null), never guessed.
 */
class SessionUptimeTracker(private val elapsedRealtimeMillis: () -> Long) {
    /** Elapsed-realtime millis when the current protected period began, or null when unknown / not protected. */
    var startedAtMillis: Long? = null
        private set
    private var sawNotProtected = false

    /** Returns true if [startedAtMillis] changed. */
    fun onHealth(health: VpnSessionHealth): Boolean {
        val before = startedAtMillis
        if (health.isProtected()) {
            if (startedAtMillis == null && sawNotProtected) {
                startedAtMillis = try {
                    elapsedRealtimeMillis()
                } catch (e: Exception) {
                    null
                }
                // Keep sawNotProtected true: an unreadable clock must not
                // flip us into "first observation" semantics later.
            }
        } else {
            sawNotProtected = true
            startedAtMillis = null
        }
        return before != startedAtMillis
    }
}

/**
 * Home dashboard - one coherent reading from the existing single sampling
 * loop (VpnTrafficIndicator): cumulative tunnel bytes of the current Connected
 * period plus the smoothed rate. [rate] is Measuring until a rate exists.
 */
data class SessionTraffic(
    val bytesReceived: Long,
    val bytesSent: Long,
    val rate: TrafficRate,
)
