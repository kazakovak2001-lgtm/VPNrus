@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.MapXrayProfileRepositoryResolver
import net.pocvpn.client.identity.MapXrayTlsProfileRepositoryResolver
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig
import net.pocvpn.client.vpn.xray.toXrayVlessTlsConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B13 (2026-08-30 correctness audit item 5) - proves VpnController.buildTransportConfig
 * actually resolves the Xray/TLS profile repository via the CURRENT attempt's
 * real endpointId (never a single flat repository, never a silent fallback
 * to ProductionGateway.ID) - the runtime-consumption half of the endpoint-
 * scoped storage layer, not merely its persistence half (see
 * XrayProfileRepositoryTest for that).
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

private val profileA = XrayProfile(
    server = "a.example.net", serverPort = 443,
    uuid = "aaaaaaaa-0000-0000-0000-000000000000",
    flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
    fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "a1a1a1a1",
)
private val profileB = XrayProfile(
    server = "b.example.net", serverPort = 443,
    uuid = "bbbbbbbb-0000-0000-0000-000000000000",
    flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
    fingerprint = "chrome", realityPublicKey = "B".repeat(43), shortId = "b1b1b1b1",
)
private val tlsProfileA = XrayTlsProfile(server = "a.example.net", serverPort = 2053, uuid = "aaaaaaaa-1111-0000-0000-000000000000", serverName = "a.example.net", fingerprint = "chrome")
private val tlsProfileB = XrayTlsProfile(server = "b.example.net", serverPort = 2053, uuid = "bbbbbbbb-1111-0000-0000-000000000000", serverName = "b.example.net", fingerprint = "chrome")

class VpnControllerXrayEndpointResolverTest {

    private val endpointA = EndpointId("gateway-a")
    private val endpointB = EndpointId("gateway-b")

    @Test
    fun `endpoint A resolves repository A, never repository B`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayProfileRepository(profileA), endpointB to FakeXrayProfileRepository(profileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, endpointA))
        runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        val sent = xrayTransport.lastConfig as TransportConfig.Xray
        assertEquals(profileA.toXrayVlessRealityConfig(), sent.config)
        assertEquals(endpointA, sent.endpointId)
    }

    @Test
    fun `endpoint B resolves repository B, never repository A`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayProfileRepository(profileA), endpointB to FakeXrayProfileRepository(profileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, endpointB))
        runCurrent()

        val sent = xrayTransport.lastConfig as TransportConfig.Xray
        assertEquals(profileB.toXrayVlessRealityConfig(), sent.config)
        assertEquals(endpointB, sent.endpointId)
    }

    @Test
    fun `TLS endpoint A resolves TLS repository A, never TLS repository B`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val resolver = MapXrayTlsProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayTlsProfileRepository(tlsProfileA), endpointB to FakeXrayTlsProfileRepository(tlsProfileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayTlsProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP, endpointA))
        runCurrent()

        val sent = tlsTransport.lastConfig as TransportConfig.XrayTls
        assertEquals(tlsProfileA.toXrayVlessTlsConfig(), sent.config)
        assertEquals(endpointA, sent.endpointId)
    }

    @Test
    fun `TLS endpoint B resolves TLS repository B, never TLS repository A`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val resolver = MapXrayTlsProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayTlsProfileRepository(tlsProfileA), endpointB to FakeXrayTlsProfileRepository(tlsProfileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayTlsProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP, endpointB))
        runCurrent()

        val sent = tlsTransport.lastConfig as TransportConfig.XrayTls
        assertEquals(tlsProfileB.toXrayVlessTlsConfig(), sent.config)
        assertEquals(endpointB, sent.endpointId)
    }

    @Test
    fun `an unknown endpoint fails closed - never silently substitutes ProductionGateway_ID`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        // Resolver only knows about the production endpoint - endpointA is unknown to it.
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(EndpointId(ProductionGateway.ID) to FakeXrayProfileRepository(profileA)),
        )
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, endpointA))
        runCurrent()

        // Never touched - the resolver returned null for endpointA, and the
        // fail-closed path never fell back to the production endpoint's
        // repository just because it happened to be the only one known.
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `switching endpoint A to B on a fresh connect does not reuse A's Xray profile`() = runTest {
        val xrayTransportA = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayTransportB = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayProfileRepository(profileA), endpointB to FakeXrayProfileRepository(profileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransportA, TransportKind.XRAY_REALITY, endpointA))
        runCurrent()
        assertEquals(profileA.toXrayVlessRealityConfig(), (xrayTransportA.lastConfig as TransportConfig.Xray).config)

        controller.disconnect()
        runCurrent()

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransportB, TransportKind.XRAY_REALITY, endpointB))
        runCurrent()

        // A fresh transport instance for endpoint B genuinely received profile B's config, not A's.
        val sentToB = xrayTransportB.lastConfig as TransportConfig.Xray
        assertEquals(profileB.toXrayVlessRealityConfig(), sentToB.config)
        assertEquals(endpointB, sentToB.endpointId)
        // The FIRST transport instance's own recorded config is untouched - never rewritten in place.
        assertEquals(profileA.toXrayVlessRealityConfig(), (xrayTransportA.lastConfig as TransportConfig.Xray).config)
    }

    @Test
    fun `permission continuation resumes with the same endpoint-scoped repository the original attempt resolved`() = runTest {
        val permissionIntent = android.content.Intent()
        val xrayTransport = FakeVpnTransport(permission = permissionIntent, kind = TransportKind.XRAY_REALITY)
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayProfileRepository(profileA), endpointB to FakeXrayProfileRepository(profileB)),
        )
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, endpointB))
        runCurrent()
        assertEquals(0, xrayTransport.connectCallCount) // deferred - waiting on permission

        controller.onVpnPermissionResult(true)
        runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        val sent = xrayTransport.lastConfig as TransportConfig.Xray
        assertEquals(profileB.toXrayVlessRealityConfig(), sent.config)
        assertEquals(endpointB, sent.endpointId)
    }

    @Test
    fun `AWG failure followed by an Xray failover for a non-production endpoint keeps that SAME endpoint, never reverting to ProductionGateway_ID`() = runTest {
        val awgTransport = FakeVpnTransport()
        awgTransport.handshakeAvailable = false
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val resolver = MapXrayProfileRepositoryResolver(
            mapOf(endpointA to FakeXrayProfileRepository(profileA)),
        )
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepositoryResolver = resolver,
        )

        // Initial AWG attempt for endpoint A fails.
        controller.connect(TransportOrchestrator.Resolution.Resolved(awgTransport, TransportKind.AMNEZIA_WG, endpointA))
        runCurrent()

        // Simulated failover (mirrors MainViewModel.maybeFailoverToXray): the
        // SAME endpointA is threaded into the Xray resolution, never
        // defaulting back to the production endpoint.
        controller.disconnect()
        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, endpointA))
        runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        val sent = xrayTransport.lastConfig as TransportConfig.Xray
        assertEquals(profileA.toXrayVlessRealityConfig(), sent.config)
        assertEquals(endpointA, sent.endpointId)
    }
}
