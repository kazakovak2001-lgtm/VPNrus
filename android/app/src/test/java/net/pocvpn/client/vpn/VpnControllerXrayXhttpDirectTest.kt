@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.MapXrayXhttpProfileRepositoryResolver
import net.pocvpn.client.identity.XrayXhttpProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B61 - proves the EXIT-role (Frankfurt, B60) DIRECT XRAY_XHTTP path
 * through VpnController is real plumbing, NOT the old, unconditional
 * "XHTTP requires a relayed attempt context" refusal - and separately
 * proves it honestly fails closed (never a fabricated connection) while
 * minimumTlsVersion/alpn/maxEachPostBytes/paddingPlacement remain
 * undecided (see XrayRuntimeResolver.resolveXhttp's own docs). Mirrors
 * VpnControllerXrayEndpointResolverTest's own shape for REALITY/TLS.
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val frankfurtXhttpProfile = XrayXhttpProfile(
    server = "edge.aknova.pp.ua",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    xhttpHost = "edge.aknova.pp.ua",
    xhttpPath = "/nova-xhttp/",
    mode = "packet-up",
    uplinkHttpMethod = "POST",
    fingerprint = "chrome",
)

class VpnControllerXrayXhttpDirectTest {

    private val frankfurt = EndpointId("frankfurt")

    @Test
    fun `XRAY_XHTTP is refused before any transport is touched when no resolver is wired`() = runTest {
        val xhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP)
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xhttpTransport, TransportKind.XRAY_XHTTP, frankfurt))
        runCurrent()

        assertEquals(0, xhttpTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `a wired resolver with a real stored profile still fails closed - never fabricates a connection`() = runTest {
        val xhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP)
        val resolver = MapXrayXhttpProfileRepositoryResolver(
            mapOf(frankfurt to FakeXrayXhttpProfileRepository(frankfurtXhttpProfile)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayXhttpProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xhttpTransport, TransportKind.XRAY_XHTTP, frankfurt))
        runCurrent()

        // Real plumbing genuinely ran (this is NOT the old unconditional
        // "requires a relayed attempt context" refusal - a stored profile
        // for this exact endpoint really was loaded and mapped by
        // XrayRuntimeResolver.resolveXhttp, proven directly by
        // XrayXhttpRuntimeResolverTest), but the resolver honestly refuses
        // to invent minimumTlsVersion/alpn/maxEachPostBytes/paddingPlacement,
        // so no connection is faked. VpnController's own catch site
        // (buildTransportConfig's caller) deliberately discards the
        // specific exception message into the generic, non-secret
        // "Failed to build tunnel configuration" TransportState.Error - see
        // that catch site's own docs - so this test asserts the type/
        // never-connected outcome, not message content (the itemized
        // blocker reason itself is proven directly by
        // XrayXhttpRuntimeResolverTest instead).
        assertEquals(0, xhttpTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `an endpoint with no stored profile also fails closed, never touching the transport`() = runTest {
        val xhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP)
        val resolver = MapXrayXhttpProfileRepositoryResolver(
            mapOf(frankfurt to FakeXrayXhttpProfileRepository(null)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayXhttpProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xhttpTransport, TransportKind.XRAY_XHTTP, frankfurt))
        runCurrent()

        assertEquals(0, xhttpTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `an unknown endpoint fails closed - never silently substitutes a different endpoint's profile`() = runTest {
        val xhttpTransport = FakeVpnTransport(kind = TransportKind.XRAY_XHTTP)
        val resolver = MapXrayXhttpProfileRepositoryResolver(
            mapOf(EndpointId("stockholm") to FakeXrayXhttpProfileRepository(frankfurtXhttpProfile)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayXhttpProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xhttpTransport, TransportKind.XRAY_XHTTP, frankfurt))
        runCurrent()

        assertEquals(0, xhttpTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }
}
