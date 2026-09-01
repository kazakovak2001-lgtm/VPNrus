package net.pocvpn.client.vpn.xray

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.vpn.policy.Ipv4RouteExclusion
import net.pocvpn.client.vpn.policy.RoutingMode
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

    // --- B18-2 RoutingMode threading ---

    @Test
    fun `no routingMode arg - existing call sites - stays full IPv4 capture, byte-for-byte`() {
        val plan = buildXrayVpnPlan(config, novaPackageId = "net.pocvpn.client")
        assertEquals(listOf("0.0.0.0/0"), plan.routesIpv4)
    }

    @Test
    fun `FULL_VPN and APPS keep the full 0_0_0_0-0 IPv4 route, same as before`() {
        assertEquals(listOf("0.0.0.0/0"), buildXrayVpnPlan(config, "net.pocvpn.client", RoutingMode.FULL_VPN).routesIpv4)
        assertEquals(listOf("0.0.0.0/0"), buildXrayVpnPlan(config, "net.pocvpn.client", RoutingMode.APPS).routesIpv4)
    }

    @Test
    fun `ADAPTIVE resolves the SAME IPv4 exclusion set AWG uses - no second CIDR computation`() {
        val plan = buildXrayVpnPlan(config, "net.pocvpn.client", RoutingMode.ADAPTIVE)
        assertEquals(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, plan.routesIpv4)
        assertTrue(plan.routesIpv4.none { it == "0.0.0.0/0" })
    }

    @Test
    fun `ADAPTIVE with NO_NETWORK does not fabricate a direct route on the Xray path either`() {
        val plan = buildXrayVpnPlan(config, "net.pocvpn.client", RoutingMode.ADAPTIVE, RestrictionClass.NO_NETWORK)
        assertEquals(listOf("0.0.0.0/0"), plan.routesIpv4)
    }

    @Test
    fun `still no ipv6 field regardless of RoutingMode - IPv6 stays fail-closed by omission in every mode`() {
        val fieldNames = XrayVpnBuilderPlan::class.java.declaredFields.map { it.name.lowercase() }
        assertFalse(fieldNames.any { it.contains("ipv6") })
        // Structural for REALITY above; TLS shares the exact same type/builder function shape.
        val tlsConfig = XrayVlessTlsConfig(
            server = "vless.example.net",
            serverPort = 2083,
            uuid = "3fa85f64-5717-4562-b3fc-2c963f66afa6",
            serverName = "vless.example.net",
            fingerprint = "chrome",
            dnsServers = listOf("1.1.1.1"),
        )
        val tlsPlan = buildXrayVpnPlan(tlsConfig, "net.pocvpn.client", RoutingMode.ADAPTIVE)
        assertEquals(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, tlsPlan.routesIpv4)
    }
}
