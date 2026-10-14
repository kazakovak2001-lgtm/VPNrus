package net.pocvpn.client.vpn.xray

import net.pocvpn.client.transport.TransportStats
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL7 for Xray: the resetting `queryAllOutboundTrafficStats()` readings
 * are summed per session in `:xray`, only for the VLESS tunnel outbounds,
 * and handed to VpnController as uplink = sent / downlink = received.
 */
class XrayTrafficCountersTest {

    private val realityTag = "nova-vless-reality-out"

    @Test
    fun `resetting readings accumulate into session totals`() {
        val counters = XrayTrafficCounters()
        counters.reset(7L)

        counters.add("$realityTag,uplink,100;$realityTag,downlink,40;")
        val totals = counters.add("$realityTag,uplink,25;")

        assertEquals(XrayTrafficCounters.Totals(7L, uplinkBytes = 125L, downlinkBytes = 40L), totals)
    }

    @Test
    fun `a new session starts from zero`() {
        val counters = XrayTrafficCounters()
        counters.reset(1L)
        counters.add("$realityTag,uplink,100;$realityTag,downlink,40;")

        counters.reset(2L)

        assertEquals(XrayTrafficCounters.Totals(2L, 0L, 0L), counters.add(""))
    }

    @Test
    fun `non-tunnel outbounds and malformed entries are ignored, never guessed`() {
        val counters = XrayTrafficCounters()
        counters.reset(3L)

        val totals = counters.add(
            "direct,uplink,999;block,downlink,999;$realityTag,sideways,5;$realityTag,uplink,abc;" +
                "$realityTag,uplink;$realityTag,downlink,-4;garbage;;$realityTag,downlink,8;",
        )

        assertEquals(XrayTrafficCounters.Totals(3L, uplinkBytes = 0L, downlinkBytes = 8L), totals)
    }

    @Test
    fun `totals saturate instead of overflowing`() {
        val counters = XrayTrafficCounters()
        counters.reset(4L)
        counters.add("$realityTag,uplink,${Long.MAX_VALUE};")

        assertEquals(Long.MAX_VALUE, counters.add("$realityTag,uplink,10;").uplinkBytes)
    }

    @Test
    fun `every renderer tag is counted as tunnel traffic`() {
        assertEquals(
            setOf("nova-vless-reality-out", "nova-vless-tls-out", "nova-vless-xhttp-out"),
            XrayConfigRenderer.TUNNEL_OUTBOUND_TAGS,
        )
    }

    @Test
    fun `renderers enable outbound uplink and downlink counters`() {
        val reality = XrayVlessRealityConfig(
            server = "vless.example.net", serverPort = 443, uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
            realityPublicKey = "A".repeat(43), shortId = "ab12cd34", mtu = 1420,
        )
        val tls = XrayVlessTlsConfig(
            server = "vless.example.net", serverPort = 443, uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            serverName = "vpn.example.invalid", fingerprint = "chrome", mtu = 1420,
        )
        val xhttp = XrayVlessXhttpConfig(
            server = "edge.example.org", serverPort = 443, uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            tlsServerName = "edge.example.org", fingerprint = "chrome", minimumTlsVersion = XrayXhttpMinimumTlsVersion.TLS_1_3,
            alpn = "h2", xhttpHost = "edge.example.org", xhttpPath = "/xhttp/", queryParameters = emptyMap(), headers = emptyMap(),
            mode = XrayXhttpMode.PACKET_UP, uplinkHttpMethod = XrayXhttpUplinkHttpMethod.POST, maxEachPostBytes = 524288,
            paddingPlacement = XrayXhttpPaddingPlacement.QUERY, paddingMinBytes = 1, paddingMaxBytes = 64,
        )

        for (rendered in listOf(XrayConfigRenderer.render(reality), XrayConfigRenderer.render(tls), XrayConfigRenderer.render(xhttp))) {
            val root = JSONObject(rendered)
            assertEquals(0, root.getJSONObject("stats").length())
            val system = root.getJSONObject("policy").getJSONObject("system")
            assertTrue(system.getBoolean("statsOutboundUplink"))
            assertTrue(system.getBoolean("statsOutboundDownlink"))
            assertEquals(setOf("statsOutboundUplink", "statsOutboundDownlink"), system.keys().asSequence().toSet())
            val tag = root.getJSONArray("outbounds").getJSONObject(0).getString("tag")
            assertTrue(tag in XrayConfigRenderer.TUNNEL_OUTBOUND_TAGS)
        }
    }

    @Test
    fun `totals map to Counters only for the owning session`() {
        val totals = XrayTrafficCounters.Totals(sessionId = 9L, uplinkBytes = 300L, downlinkBytes = 120L)

        assertEquals(
            TransportStats.Counters(bytesReceived = 120L, bytesSent = 300L, lastHandshakeEpochMillis = null),
            XrayProcessBridge.dataPlaneStatsFor(9L, totals),
        )
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.dataPlaneStatsFor(8L, totals))
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.dataPlaneStatsFor(null, totals))
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.dataPlaneStatsFor(9L, null))
    }
}
