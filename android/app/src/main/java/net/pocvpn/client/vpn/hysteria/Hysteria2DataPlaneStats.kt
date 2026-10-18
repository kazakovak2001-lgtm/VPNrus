package net.pocvpn.client.vpn.hysteria

import net.pocvpn.client.transport.TransportStats
import org.json.JSONObject

/** One line of the tun2socks child's stats stream (`dataplane_stats.go`): payload counters only, never addresses or credentials. */
internal data class Tun2SocksStatsLine(val pid: Int, val seq: Long, val txBytes: Long, val rxBytes: Long)

/** Strict parse; anything malformed, negative or of another type is null (the tracker then fails closed). */
internal fun parseTun2SocksStatsLine(raw: String): Tun2SocksStatsLine? = try {
    val obj = JSONObject(raw.trim())
    if (obj.optString("type") != "stats" || obj.length() != 5) {
        null
    } else {
        val line = Tun2SocksStatsLine(obj.getInt("pid"), obj.getLong("seq"), obj.getLong("tx"), obj.getLong("rx"))
        line.takeIf { it.pid > 0 && it.seq > 0 && it.txBytes >= 0 && it.rxBytes >= 0 }
    }
} catch (t: Throwable) {
    null
}

/**
 * H2-GATE (S2) - the session-scoped view of ONE tun2socks child's stats
 * stream, the only Hysteria2 evidence that covers the TUN -> tun2socks leg
 * (see `Hysteria2VpnService`'s CONNECTED DEFINITION). Bound to the child pid
 * from that session's own ack, so another child's stream is never accepted.
 *
 * Fail-closed rules, all permanent for the session once tripped: a line from
 * another pid, a non-increasing seq, a counter going backwards, a malformed
 * line, or the stream ending. [snapshot] then reports
 * [TransportStats.Unsupported], which ends the B-WL7 sampling with no
 * verdict - the session can never reach Protected from it. A healthy stream
 * whose last line is older than [staleAfterMillis] reports
 * [TransportStats.Unavailable]: no sample is taken, so silence in the stream
 * is never read as either progress or a stall.
 */
class Hysteria2DataPlaneStatsTracker internal constructor(
    private val expectedPid: Int,
    private val nowMillis: () -> Long,
    private val staleAfterMillis: Long = STALE_AFTER_MILLIS,
) {
    private val lock = Any()
    private var last: Tun2SocksStatsLine? = null
    private var lastReceivedAtMillis = 0L
    private var broken = false

    fun accept(raw: String) {
        val line = parseTun2SocksStatsLine(raw)
        synchronized(lock) {
            if (broken) return
            val previous = last
            val valid = line != null && line.pid == expectedPid &&
                (previous == null || (line.seq > previous.seq && line.txBytes >= previous.txBytes && line.rxBytes >= previous.rxBytes))
            if (!valid) {
                broken = true
                return
            }
            last = line
            lastReceivedAtMillis = nowMillis()
        }
    }

    /** The stream ended (EOF, read error, channel closed) - no further evidence can arrive for this session. */
    fun streamEnded() = synchronized(lock) { broken = true }

    fun snapshot(): TransportStats = synchronized(lock) {
        val line = last
        when {
            broken -> TransportStats.Unsupported
            line == null || nowMillis() - lastReceivedAtMillis > staleAfterMillis -> TransportStats.Unavailable
            else -> TransportStats.Counters(bytesReceived = line.rxBytes, bytesSent = line.txBytes, lastHandshakeEpochMillis = null)
        }
    }

    companion object {
        /** Three missed 1 s stats intervals plus margin. */
        const val STALE_AFTER_MILLIS = 3_500L
        const val MAX_LINE_LENGTH = 512
    }
}
