@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.policy.Ipv4RouteExclusion
import net.pocvpn.client.vpn.policy.RoutingMode
import net.pocvpn.client.vpn.xray.buildXrayVpnPlan
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val VALID_XRAY_PROFILE = XrayProfile(
    server = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
)

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

    // --- B18-2: consistency across live transports ---

    @Test
    fun `AWG ADAPTIVE and Xray ADAPTIVE resolve the exact same IPv4 route set`() = runTest {
        val (controller, transport) = controllerWith(RoutingMode.ADAPTIVE)
        controller.connect()
        runCurrent()
        val awgIpv4Routes = lastAwgConfig(transport).peer.allowedIps.filterNot { it.contains(":") }

        val xrayRoutes = buildXrayVpnPlan(VALID_XRAY_PROFILE.toXrayVlessRealityConfig(), "net.pocvpn.client", RoutingMode.ADAPTIVE).routesIpv4

        assertEquals(awgIpv4Routes, xrayRoutes)
        assertEquals(Ipv4RouteExclusion.ADAPTIVE_DIRECT_IPV4_ROUTES, xrayRoutes)
    }

    @Test
    fun `FULL_VPN and APPS remain full tunnel on both AWG and Xray transports`() {
        for (mode in listOf(RoutingMode.FULL_VPN, RoutingMode.APPS)) {
            val xrayRoutes = buildXrayVpnPlan(VALID_XRAY_PROFILE.toXrayVlessRealityConfig(), "net.pocvpn.client", mode).routesIpv4
            assertEquals("mode=$mode", listOf("0.0.0.0/0"), xrayRoutes)
        }
    }

    @Test
    fun `VpnController actually threads RoutingMode into TransportConfig_Xray - not just the plan builder in isolation`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            routingModeStore = FakeRoutingModeStore(RoutingMode.ADAPTIVE),
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        val sentConfig = xrayTransport.lastConfig as TransportConfig.Xray
        assertEquals(RoutingMode.ADAPTIVE, sentConfig.routingMode)
    }

    @Test
    fun `AWG-to-Xray failover cannot broaden or narrow routing - both resolve identically for the SAME saved mode`() = runTest {
        // Simulates what AwgXrayFailoverPolicy actually threads across a
        // failover: the SAME VpnController instance (same routingModeStore/
        // restrictionClassProvider), a different resolved transport/kind.
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            routingModeStore = FakeRoutingModeStore(RoutingMode.ADAPTIVE),
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(awgTransport, TransportKind.AMNEZIA_WG))
        runCurrent()
        val awgIpv4Routes = lastAwgConfig(awgTransport).peer.allowedIps.filterNot { it.contains(":") }
        controller.disconnect()
        runCurrent()

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()
        val xraySentConfig = xrayTransport.lastConfig as TransportConfig.Xray
        val xrayIpv4Routes = buildXrayVpnPlan(xraySentConfig.config, "net.pocvpn.client", xraySentConfig.routingMode).routesIpv4

        assertEquals(RoutingMode.ADAPTIVE, xraySentConfig.routingMode)
        assertEquals(awgIpv4Routes, xrayIpv4Routes)
    }

    @Test
    fun `routing decisions never select a transport or gateway - VpnController's transport choice is untouched by RoutingMode`() = runTest {
        // The transport actually used (AMNEZIA_WG vs XRAY_REALITY) is chosen
        // entirely by what connect() is called with (SmartConnect/failover's
        // own job) - RoutingMode only ever changes the route LIST inside
        // whichever TransportConfig gets built, never which kind is built.
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            routingModeStore = FakeRoutingModeStore(RoutingMode.ADAPTIVE),
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(0, awgTransport.connectCallCount)
    }
}
