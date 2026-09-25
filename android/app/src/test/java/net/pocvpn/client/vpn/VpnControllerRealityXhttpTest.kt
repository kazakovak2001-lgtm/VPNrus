@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.REALITY_XHTTP_MODE_METADATA_KEY
import net.pocvpn.client.reachability.REALITY_XHTTP_PATH_METADATA_KEY
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.XrayXhttpMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL-R6 - VLESS + REALITY + XHTTP through the real VpnController: the
 * device's REALITY credentials + the signed binding's host/port/path/mode,
 * Vision flow dropped, and every missing piece fails closed.
 */
class VpnControllerRealityXhttpTest {

    private fun gateway() = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10", endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0"), profile = AwgProfile.none(),
    )

    private val profile = XrayProfile(
        server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    private fun binding(metadata: Map<String, String>, kind: TransportKind = TransportKind.XRAY_REALITY_XHTTP) =
        EndpointTransportBinding(kind, "203.0.113.77", 2083, metadata)

    private fun transport() = FakeVpnTransport(kind = TransportKind.XRAY_REALITY_XHTTP, capabilities = TransportCapabilities.xrayRealityXhttpAdapterShell())

    private fun controller(diagnostics: DiagnosticsStore, scope: kotlinx.coroutines.CoroutineScope, xrayProfile: XrayProfile? = profile) = VpnController(
        FakeVpnTransport(), FakeClientKeyRepository(), FakeGatewayConfigurationRepository(gateway()),
        FakeReconnectManager(), diagnostics, scope,
        xrayProfileRepository = FakeXrayProfileRepository(xrayProfile),
    )

    private fun resolved(t: FakeVpnTransport, b: EndpointTransportBinding?) = TransportOrchestrator.Resolution.Resolved(
        t, TransportKind.XRAY_REALITY_XHTTP, endpointTransportBinding = b,
    )

    @Test
    fun `builds the config from the device REALITY profile plus the signed binding, without Vision flow`() = runTest {
        val t = transport()
        val c = controller(DiagnosticsStore(), backgroundScope)
        c.connect(resolved(t, binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/", REALITY_XHTTP_MODE_METADATA_KEY to "packet-up"))))
        runCurrent()
        assertTrue(c.state.value is TransportState.Connected)
        val config = t.lastConfig as TransportConfig.XrayRealityXhttp
        assertEquals("203.0.113.77", config.config.reality.server)
        assertEquals(2083, config.config.reality.serverPort)
        assertEquals("", config.config.reality.flow)
        assertEquals("www.microsoft.com", config.config.reality.serverName)
        assertEquals("A".repeat(43), config.config.reality.realityPublicKey)
        assertEquals("/nx7/", config.config.xhttpPath)
        assertEquals(XrayXhttpMode.PACKET_UP, config.config.mode)
        assertEquals(ProductionGateway.ID, config.endpointId.value)
    }

    @Test
    fun `fails closed without a pinned binding, with unsigned facts, with a wrong-kind binding, or without a REALITY profile`() = runTest {
        val cases = listOf(
            null to profile,
            binding(emptyMap()) to profile,
            binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/"), TransportKind.XRAY_REALITY) to profile,
            binding(mapOf(REALITY_XHTTP_PATH_METADATA_KEY to "/nx7/")) to null,
        )
        cases.forEach { (b, p) ->
            val diagnostics = DiagnosticsStore()
            val t = transport()
            val c = controller(diagnostics, backgroundScope, xrayProfile = p)
            c.connect(resolved(t, b))
            runCurrent()
            assertTrue("case binding=$b profile=${p != null}", c.state.value is TransportState.Error)
            assertEquals(0, t.connectCallCount)
            assertTrue(diagnostics.snapshot.value.lastError is VpnError.ConfigurationMappingFailure)
        }
    }
}
