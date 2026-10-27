package net.pocvpn.client.vpn.protection

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.config.VpnDnsPolicy
import net.pocvpn.client.vpn.policy.Ipv4RouteExclusion
import net.pocvpn.client.vpn.xray.XrayVlessRealityConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelProtectionCheckTest {

    private val dns = listOf("1.1.1.1", "1.0.0.1")

    private fun check(routes: List<String>, dnsServers: List<String> = dns, v6Address: Boolean = false) =
        TunnelProtectionCheck.evaluate(TunnelLinkSnapshot(routes, dnsServers, v6Address))

    @Test
    fun `AWG full tunnel with a captured IPv6 default route is VERIFIED`() {
        val r = check(listOf("0.0.0.0/0", "::/0"), v6Address = true)
        assertEquals(TunnelProtectionStatus.VERIFIED, r.status)
        assertEquals("CAPTURED", r.ipv6)
    }

    @Test
    fun `Xray full tunnel with no IPv6 at all is VERIFIED - Android blocks the family`() {
        val r = check(listOf("0.0.0.0/0"))
        assertEquals(TunnelProtectionStatus.VERIFIED, r.status)
        assertEquals("BLOCKED", r.ipv6)
    }

    @Test
    fun `ADAPTIVE routes without the local private ranges still cover the public internet`() {
        val r = check(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES)
        assertEquals(TunnelProtectionStatus.VERIFIED, r.status)
    }

    @Test
    fun `a narrow IPv4 route set is a suspected leak`() {
        val r = check(listOf("10.77.0.0/24", "1.0.0.0/8"))
        assertEquals(TunnelProtectionStatus.LEAK_SUSPECTED, r.status)
        assertTrue(TunnelProtectionFinding.IPV4_PUBLIC_NOT_COVERED in r.findings)
    }

    @Test
    fun `unexpected DNS servers are reported`() {
        val r = check(listOf("0.0.0.0/0"), dnsServers = listOf("192.168.1.1"))
        assertTrue(TunnelProtectionFinding.DNS_SERVERS_UNEXPECTED in r.findings)
        // 192.168.1.1 is still inside 0.0.0.0/0, so it is not also "outside the tunnel".
        assertFalse(TunnelProtectionFinding.DNS_SERVER_NOT_IN_TUNNEL in r.findings)
    }

    @Test
    fun `a DNS server outside every tunnel route is reported`() {
        val r = check(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, dnsServers = listOf("1.1.1.1", "192.168.1.1"))
        assertTrue(TunnelProtectionFinding.DNS_SERVER_NOT_IN_TUNNEL in r.findings)
    }

    @Test
    fun `an IPv6 address without a full IPv6 route is a suspected leak`() {
        val r = check(listOf("0.0.0.0/0"), v6Address = true)
        assertEquals("PARTIAL", r.ipv6)
        assertTrue(TunnelProtectionFinding.IPV6_NOT_FULLY_CAPTURED in r.findings)
    }

    @Test
    fun `a partial IPv6 route set is a suspected leak`() {
        val r = check(listOf("0.0.0.0/0", "2000::/4"))
        assertEquals("PARTIAL", r.ipv6)
    }

    @Test
    fun `no visible VPN network is NOT_VERIFIABLE and claims nothing`() {
        val r = TunnelProtectionCheck.evaluate(null)
        assertEquals(TunnelProtectionStatus.NOT_VERIFIABLE, r.status)
        assertTrue(r.findings.isEmpty())
        assertNull(r.ipv6)
    }

    @Test
    fun `cidrContains handles both families, prefix edges and malformed input`() {
        assertTrue(TunnelProtectionCheck.cidrContains("0.0.0.0/0", "8.8.8.8"))
        assertTrue(TunnelProtectionCheck.cidrContains("1.1.1.0/24", "1.1.1.255"))
        assertFalse(TunnelProtectionCheck.cidrContains("1.1.1.0/24", "1.1.2.0"))
        assertTrue(TunnelProtectionCheck.cidrContains("::/0", "2606:4700:4700::1111"))
        assertFalse(TunnelProtectionCheck.cidrContains("::/0", "8.8.8.8"))
        assertFalse(TunnelProtectionCheck.cidrContains("not-a-cidr", "8.8.8.8"))
        assertFalse(TunnelProtectionCheck.cidrContains("0.0.0.0/33", "8.8.8.8"))
        assertFalse(TunnelProtectionCheck.cidrContains("0.0.0.0/0", "example.com"))
    }

    @Test
    fun `none of the public IPv4 samples is in a range ADAPTIVE leaves outside the tunnel`() {
        TunnelProtectionCheck.PUBLIC_IPV4_SAMPLES.forEach { ip ->
            assertTrue(ip, Ipv4RouteExclusion.LOCAL_PRIVATE_RANGES.none { TunnelProtectionCheck.cidrContains(it, ip) })
        }
    }

    @Test
    fun `the log keeps the newest records and renders the report section`() {
        val log = TunnelProtectionLog(capacity = 2) { 7L }
        val ok = TunnelProtectionResult(TunnelProtectionStatus.VERIFIED, emptyList(), "BLOCKED")
        repeat(3) { log.record(TransportKind.XRAY_REALITY, ok, reads = 1, generation = it.toLong()) }
        val records = log.snapshot()
        assertEquals(listOf(2L, 3L), records.map { it.checkId })
        val json = TunnelProtectionLog.reportJson(records)
        assertEquals("RECORDED", json.getString("status"))
        val item = json.getJSONArray("items").getJSONObject(1)
        assertEquals("VERIFIED", item.getString("status"))
        assertEquals("XRAY_REALITY", item.getString("transport"))
        assertEquals("BLOCKED", item.getString("ipv6"))
        assertEquals("EMPTY", TunnelProtectionLog.reportJson(emptyList()).getString("status"))
    }

    @Test
    fun `expected DNS follows the transport's own config, not one global list`() {
        val reality = XrayVlessRealityConfig(
            server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
            flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
            realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
        )
        assertEquals(XrayVlessRealityConfig.DEFAULT_DNS_SERVERS, TunnelProtectionCheck.expectedDns(TransportConfig.Xray(reality)))
        assertEquals(VpnDnsPolicy.servers, TunnelProtectionCheck.expectedDns(null))
    }

    @Test
    fun `Xray's own DNS list is VERIFIED against that list - the field false positive`() {
        val xrayDns = XrayVlessRealityConfig.DEFAULT_DNS_SERVERS
        val r = TunnelProtectionCheck.evaluate(TunnelLinkSnapshot(listOf("0.0.0.0/0", "::/0"), xrayDns, true), xrayDns)
        assertEquals(TunnelProtectionStatus.VERIFIED, r.status)
        assertTrue(r.findings.isEmpty())
    }
}
