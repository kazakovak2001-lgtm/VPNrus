@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val PROFILE_ON_2053 = XrayProfile(
    server = "152.70.43.1",
    serverPort = 2053,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.wikipedia.org",
    fingerprint = "chrome",
    realityPublicKey = "A".repeat(43),
    shortId = "a1b2c3d4",
)

private fun gateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

/**
 * The signed manifest binding is authoritative for a Direct XRAY_REALITY
 * attempt's port, so a gateway can move REALITY (Frankfurt 2053 -> 443) with
 * a new manifest only; the per-device profile keeps supplying identity.
 */
class VpnControllerRealitySignedPortTest {

    private fun controller(scope: kotlinx.coroutines.CoroutineScope) = VpnController(
        FakeVpnTransport(), FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(gateway()),
        FakeReconnectManager(), DiagnosticsStore(), scope,
        xrayProfileRepository = FakeXrayProfileRepository(PROFILE_ON_2053),
    )

    private fun sentReality(transport: FakeVpnTransport) = (transport.lastConfig as TransportConfig.Xray).config

    @Test
    fun `a pinned signed binding on 443 overrides the stored profile's 2053, identity unchanged`() = runTest {
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        controller(backgroundScope).connect(
            TransportOrchestrator.Resolution.Resolved(
                xray, TransportKind.XRAY_REALITY,
                endpointTransportBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 443),
            ),
        )
        runCurrent()

        val sent = sentReality(xray)
        assertEquals(443, sent.serverPort)
        assertEquals("152.70.43.1", sent.server)
        assertEquals(PROFILE_ON_2053.uuid, sent.uuid)
        assertEquals("www.wikipedia.org", sent.serverName)
        assertEquals(PROFILE_ON_2053.shortId, sent.shortId)
    }

    @Test
    fun `no pinned binding keeps the stored profile port (legacy path)`() = runTest {
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        controller(backgroundScope).connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(2053, sentReality(xray).serverPort)
    }

    @Test
    fun `a profile issued for another host than the signed binding fails closed`() = runTest {
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = controller(backgroundScope)
        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                xray, TransportKind.XRAY_REALITY,
                endpointTransportBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "16.170.208.231", 443),
            ),
        )
        runCurrent()

        assertEquals(0, xray.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `a binding of another kind is ignored`() = runTest {
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        controller(backgroundScope).connect(
            TransportOrchestrator.Resolution.Resolved(
                xray, TransportKind.XRAY_REALITY,
                endpointTransportBinding = EndpointTransportBinding(TransportKind.TLS_TCP, "152.70.43.1", 2083),
            ),
        )
        runCurrent()

        assertEquals(2053, sentReality(xray).serverPort)
    }
}
