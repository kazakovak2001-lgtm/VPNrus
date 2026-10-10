package net.pocvpn.client.vpn.xray

/**
 * B-WL7 for Xray - cumulative tunnel-outbound byte totals for ONE `:xray`
 * core session, built from the pinned AAR's
 * `CoreController.queryAllOutboundTrafficStats()`.
 *
 * That native call READS AND RESETS every outbound counter and returns
 * `tag,direction,value;tag,direction,value;` (only non-zero counters - see
 * AndroidLibXrayLite c634d1b `libv2ray_utils.go`). Because every query
 * resets, the running totals have to live here, in the `:xray` process,
 * next to the core: [add] folds one reading in, [reset] starts a new
 * session.
 *
 * What is counted: xray-core v26.7.28 wraps the outbound connection
 * returned by `internet.Dial` (i.e. AFTER TLS/REALITY/XHTTP security is
 * applied) in a CounterConnection - so uplink/downlink are VLESS stream
 * bytes, not TLS handshake or TCP ACK bytes. A server that accepts the
 * handshake but never returns data therefore shows uplink growth with a
 * flat downlink - exactly the shape TrafficProgressMonitor judges.
 *
 * Only [tunnelOutboundTags] are summed (the VLESS outbounds
 * [XrayConfigRenderer] renders), so a future non-tunnel outbound
 * (direct/block) could never count as tunnel progress. Malformed entries
 * are skipped, never guessed. Thread-safe.
 */
class XrayTrafficCounters(private val tunnelOutboundTags: Set<String> = XrayConfigRenderer.TUNNEL_OUTBOUND_TAGS) {

    data class Totals(val sessionId: Long, val uplinkBytes: Long, val downlinkBytes: Long)

    private var sessionId: Long = 0L
    private var uplink: Long = 0L
    private var downlink: Long = 0L

    @Synchronized
    fun reset(newSessionId: Long) {
        sessionId = newSessionId
        uplink = 0L
        downlink = 0L
    }

    /** Folds one `queryAllOutboundTrafficStats()` reading in and returns the new totals. */
    @Synchronized
    fun add(reading: String): Totals {
        for (entry in reading.split(';')) {
            val parts = entry.split(',')
            if (parts.size != 3 || parts[0] !in tunnelOutboundTags) continue
            val value = parts[2].toLongOrNull()?.takeIf { it > 0 } ?: continue
            when (parts[1]) {
                "uplink" -> uplink = saturatingAdd(uplink, value)
                "downlink" -> downlink = saturatingAdd(downlink, value)
            }
        }
        return Totals(sessionId, uplink, downlink)
    }

    private fun saturatingAdd(a: Long, b: Long): Long = if (a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b
}
