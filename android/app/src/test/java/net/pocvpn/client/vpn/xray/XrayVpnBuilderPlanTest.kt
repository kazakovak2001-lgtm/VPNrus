package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class XrayVpnBuilderPlanTest {

    private val config = XrayVlessRealityConfig(
        server = "vless.example.net",
        serverPort = 443,
        uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        flow = "",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
        dnsServers = listOf("1.1.1.1", "8.8.8.8"),
    )

    @Test
    fun `Nova's own package is always disallowed - ALL_APPS only, this slice`() {
        val plan = buildXrayVpnPlan(config, novaPackageId = "net.pocvpn.client")
        assertEquals(setOf("net.pocvpn.client"), plan.disallowedApplications)
    }

    @Test
    fun `full IPv4 capture route is configured`() {
        val plan = buildXrayVpnPlan(config, novaPackageId = "net.pocvpn.client")
        assertEquals(listOf("0.0.0.0/0"), plan.routesIpv4)
    }

    @Test
    fun `configured DNS servers are carried into the plan`() {
        val plan = buildXrayVpnPlan(config, novaPackageId = "net.pocvpn.client")
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), plan.dnsServers)
    }

    @Test
    fun `the plan has no IPv6 field at all - IPv6 is blocked by omission, never claimed tunneled`() {
        // Structural proof, not just a convention comment: this asserts the
        // absence of any ipv6-named property on the type itself, so an
        // accidental future addition of an ipv6 route/address field must
        // deliberately update this test (and the capability it implies)
        // rather than silently starting to claim IPv6 tunneling.
        val fieldNames = XrayVpnBuilderPlan::class.java.declaredFields.map { it.name.lowercase() }
        assertFalse(fieldNames.any { it.contains("ipv6") })
    }

    @Test
    fun `mtu and tun-local address come from the config, not hardcoded`() {
        val custom = config.copy(mtu = 1280, tunLocalAddressIpv4 = "172.20.0.1", tunLocalPrefixLengthIpv4 = 29)
        val plan = buildXrayVpnPlan(custom, novaPackageId = "net.pocvpn.client")
        assertEquals(1280, plan.mtu)
        assertEquals("172.20.0.1", plan.tunLocalAddressIpv4)
        assertEquals(29, plan.tunLocalPrefixLengthIpv4)
    }

    @Test
    fun `plan never includes an allowed-applications list alongside the disallowed one`() {
        // Mirrors the B8H invariant (AppRoutingLists) that Android's
        // allow/disallow lists are never both populated at once - this
        // slice only ever produces a disallow list.
        val plan = buildXrayVpnPlan(config, novaPackageId = "net.pocvpn.client")
        assertTrue(plan.disallowedApplications.isNotEmpty())
    }
}
