package net.pocvpn.client.vpn.xray

/**
 * B-WL-R3 - turns the pinned AndroidLibXrayLite
 * `CoreController.queryAllOutboundTrafficStats()` output into cumulative
 * session byte totals.
 *
 * Source contract (AndroidLibXrayLite c634d1b, libv2ray_utils.go): a single
 * line `tag,direction,value;tag,direction,value;...` where direction is
 * `uplink` or `downlink`, and EVERY reported counter is reset to zero by the
 * query itself - so each query returns deltas since the previous one, and
 * counters that did not move are omitted. This is the wrapper's documented,
 * structured stats API, not log parsing.
 *
 * All outbound tags are summed: Nova's client configs contain exactly one
 * outbound, so the sum is that outbound's traffic. Malformed entries are
 * skipped (never guessed); a null/empty query result adds nothing. Not
 * thread-safe - owned by the single session watchdog coroutine.
 */
class XrayOutboundTrafficAccumulator {

    var uplinkBytes: Long = 0L
        private set
    var downlinkBytes: Long = 0L
        private set

    /** Adds one query result. Returns false when [raw] is null (stats unavailable), true otherwise. */
    fun add(raw: String?): Boolean {
        if (raw == null) return false
        for (entry in raw.split(';')) {
            if (entry.isBlank()) continue
            val parts = entry.split(',')
            if (parts.size != 3) continue
            val value = parts[2].trim().toLongOrNull() ?: continue
            if (value <= 0L) continue
            when (parts[1].trim()) {
                "uplink" -> uplinkBytes = saturatingAdd(uplinkBytes, value)
                "downlink" -> downlinkBytes = saturatingAdd(downlinkBytes, value)
            }
        }
        return true
    }

    fun reset() {
        uplinkBytes = 0L
        downlinkBytes = 0L
    }

    private fun saturatingAdd(a: Long, b: Long): Long = if (Long.MAX_VALUE - a < b) Long.MAX_VALUE else a + b
}
