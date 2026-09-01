@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.Ipv4RouteExclusion
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B18 - proves RoutingMode actually reaches the real AmneziaWG AllowedIPs
 * list VpnController builds - the live enforcement point for Adaptive Direct
 * Routing (see VpnController.resolveAdaptiveAllowedIps's own docs).
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    dnsServers = listOf("1.1.1.1", "1.0.0.1"),
    profile = AwgProfile.none(),
)

private fun lastAwgConfig(transport: FakeVpnTransport) = (transport.lastConfig as TransportConfig.Awg).config

class VpnControllerAdaptiveRoutingTest {

    private fun TestScope.controllerWith(routingMode: RoutingMode, restrictionClass: RestrictionClass? = null): Pair<VpnController, FakeVpnTransport> {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            routingModeStore = FakeRoutingModeStore(routingMode),
            restrictionClassProvider = restrictionClass?.let { rc -> { rc } },
        )
        return controller to transport
    }

    @Test
    fun `no routingModeStore wired - existing call sites - behaves exactly like FULL_VPN`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertEquals(listOf("0.0.0.0/0", "::/0"), lastAwgConfig(transport).peer.allowedIps)
    }

    @Test
    fun `FULL_VPN keeps the exact full-tunnel 0_0_0_0-0 route - never narrowed`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.FULL_VPN)

        controller.connect()
        runCurrent()

        assertEquals(listOf("0.0.0.0/0", "::/0"), lastAwgConfig(transport).peer.allowedIps)
    }

    @Test
    fun `APPS mode is destination-route-identical to FULL_VPN - never narrows the route set`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.APPS)

        controller.connect()
        runCurrent()

        assertEquals(listOf("0.0.0.0/0", "::/0"), lastAwgConfig(transport).peer.allowedIps)
    }

    @Test
    fun `ADAPTIVE excludes RFC1918-loopback-link-local from the IPv4 route set`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.ADAPTIVE)

        controller.connect()
        runCurrent()

        val allowedIps = lastAwgConfig(transport).peer.allowedIps
        assertEquals(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, allowedIps.filterNot { it.contains(":") })
        assertTrue(allowedIps.none { it == "0.0.0.0/0" })
    }

    @Test
    fun `ADAPTIVE never alters the IPv6 entry - IPv6 stays fail-closed exactly as before`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.ADAPTIVE)

        controller.connect()
        runCurrent()

        assertEquals(listOf("::/0"), lastAwgConfig(transport).peer.allowedIps.filter { it.contains(":") })
    }

    @Test
    fun `ADAPTIVE with NO_NETWORK restriction does not fabricate a direct route - falls back to the gateway's own allowedIps`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.ADAPTIVE, RestrictionClass.NO_NETWORK)

        controller.connect()
        runCurrent()

        assertEquals(listOf("0.0.0.0/0", "::/0"), lastAwgConfig(transport).peer.allowedIps)
    }

    @Test
    fun `ADAPTIVE with POSSIBLE_HARD_WHITELIST still only excludes local-private ranges - never a broader bypass`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.ADAPTIVE, RestrictionClass.POSSIBLE_HARD_WHITELIST)

        controller.connect()
        runCurrent()

        val allowedIps = lastAwgConfig(transport).peer.allowedIps
        assertEquals(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, allowedIps.filterNot { it.contains(":") })
    }

    @Test
    fun `changing the saved routing mode while connected does NOT rebuild the active tunnel`() = runTest {
        val transport = FakeVpnTransport()
        val store = FakeRoutingModeStore(RoutingMode.FULL_VPN)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            routingModeStore = store,
        )

        controller.connect()
        runCurrent()
        assertEquals(RoutingMode.FULL_VPN, controller.appliedRoutingMode.value)
        assertEquals(1, transport.connectCallCount)

        store.write(RoutingMode.ADAPTIVE)
        runCurrent()

        // B18 mirrors B8H's own "reconnect to apply" discipline - no automatic rebuild.
        assertEquals(1, transport.connectCallCount)
        assertEquals(RoutingMode.FULL_VPN, controller.appliedRoutingMode.value)
        assertEquals(listOf("0.0.0.0/0", "::/0"), lastAwgConfig(transport).peer.allowedIps)
    }

    @Test
    fun `disconnect clears appliedRoutingMode - a genuinely applied-not-saved distinction`() = runTest {
        val (controller, _) = controllerWith(RoutingMode.ADAPTIVE)

        controller.connect()
        runCurrent()
        assertEquals(RoutingMode.ADAPTIVE, controller.appliedRoutingMode.value)

        controller.disconnect()
        runCurrent()

        assertEquals(null, controller.appliedRoutingMode.value)
    }
}
