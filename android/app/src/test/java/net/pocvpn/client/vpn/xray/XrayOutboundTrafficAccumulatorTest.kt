package net.pocvpn.client.vpn.xray

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B-WL-R3 - parsing the pinned wrapper's queryAllOutboundTrafficStats() deltas, and enabling the counters in every rendered config. */
class XrayOutboundTrafficAccumulatorTest {

    @Test
    fun `deltas accumulate per direction across queries`() {
        val a = XrayOutboundTrafficAccumulator()
        assertTrue(a.add("nova-vless-reality-out,uplink,100;nova-vless-reality-out,downlink,2000;"))
        assertTrue(a.add("nova-vless-reality-out,downlink,500;"))
        assertEquals(100L, a.uplinkBytes)
        assertEquals(2_500L, a.downlinkBytes)
    }

    @Test
    fun `null means no counter channel, empty means nothing moved`() {
        val a = XrayOutboundTrafficAccumulator()
        assertFalse(a.add(null))
        assertTrue(a.add(""))
        assertEquals(0L, a.uplinkBytes + a.downlinkBytes)
    }

    @Test
    fun `malformed or non-positive entries are skipped, never guessed`() {
        val a = XrayOutboundTrafficAccumulator()
        a.add("x,uplink;x,downlink,abc;x,sideways,5;x,uplink,-3;x,downlink,0;;x,uplink,7;")
        assertEquals(7L, a.uplinkBytes)
        assertEquals(0L, a.downlinkBytes)
    }

    @Test
    fun `accumulation saturates instead of overflowing`() {
        val a = XrayOutboundTrafficAccumulator()
        a.add("x,downlink,${Long.MAX_VALUE};x,downlink,10;")
        assertEquals(Long.MAX_VALUE, a.downlinkBytes)
    }

    @Test
    fun `every rendered client config enables outbound traffic counters and nothing else`() {
        val reality = XrayVlessRealityConfig("vless.example.net", 443, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "xtls-rprx-vision",
            "www.microsoft.com", "chrome", "A".repeat(43), "ab12cd34")
        val rendered = listOf(
            XrayConfigRenderer.render(reality),
            XrayConfigRenderer.render(XrayVlessTlsConfig("tls.example.net", 443, "3fa85f64-5717-4562-b3fc-2c963f66afa6", "tls.example.net", "chrome")),
            XrayConfigRenderer.render(XrayVlessRealityXhttpConfig(reality.copy(flow = ""), "/nx7/")),
        )
        rendered.forEach { json ->
            val root = JSONObject(json)
            assertEquals(0, root.getJSONObject("stats").length())
            val system = root.getJSONObject("policy").getJSONObject("system")
            assertEquals(setOf("statsOutboundUplink", "statsOutboundDownlink"), system.keySet())
            assertTrue(system.getBoolean("statsOutboundUplink") && system.getBoolean("statsOutboundDownlink"))
            assertEquals(setOf("log", "stats", "policy", "inbounds", "outbounds"), root.keySet())
        }
    }
}
