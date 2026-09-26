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
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessXhttpConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B61/B61.4 - proves the EXIT-role (Frankfurt, B60) DIRECT XRAY_XHTTP path
 * through VpnController is real plumbing, NOT the old, unconditional
 * "XHTTP requires a relayed attempt context" refusal, and that a real
 * stored profile now genuinely reaches a connected transport using the
 * evidence-backed EXIT constants (B61.3/B61.4) - never the Stockholm
 * ingress profile's own values, never a fabricated padding placement.
 * Mirrors VpnControllerXrayEndpointResolverTest's own shape for REALITY/TLS.
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
    fun `a wired resolver with a real stored profile now genuinely connects using the evidence-backed EXIT constants`() = runTest {
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

        // B61.4 - this is NOT the old unconditional "requires a relayed
        // attempt context" refusal, and no longer the B61 "always rejects,
        // no source of truth" outcome either: a stored profile for this
        // exact endpoint is genuinely loaded, mapped through
        // XrayRuntimeResolver.resolveXhttp using the evidence-backed EXIT
        // constants (B61.3), and reaches the transport.
        assertEquals(1, xhttpTransport.connectCallCount)
        val sent = xhttpTransport.lastConfig as TransportConfig.XrayXhttp
        assertEquals(frankfurtXhttpProfile.toXrayVlessXhttpConfig(), sent.config)
        assertEquals(frankfurt, sent.endpointId)
        assertFalse(sent.isRelayed)
        assertEquals(null, sent.relayExitProbeHost)
        // Never a synthesized padding placement.
        assertEquals(null, sent.config.paddingPlacement)
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
