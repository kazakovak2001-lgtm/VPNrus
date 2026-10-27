@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayRealityXhttpProfile
import net.pocvpn.client.identity.XrayRealityXhttpProfileRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessRealityXhttpConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** VpnController's Direct XRAY_REALITY_XHTTP path: real stored profile in, fail closed otherwise. */
class VpnControllerRealityXhttpTest {

    private class FakeRepository(private val profile: XrayRealityXhttpProfile?) : XrayRealityXhttpProfileRepository {
        override suspend fun getProfileOrNull(): XrayRealityXhttpProfile? = profile
        override suspend fun saveProfile(profile: XrayRealityXhttpProfile) = Unit
        override suspend fun clearProfile() = Unit
    }

    private val stockholm = EndpointId("stockholm")

    private val profile = XrayRealityXhttpProfile(
        server = "16.170.208.231",
        serverPort = 8443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "ab12cd34",
        xhttpPath = "/nova-rx/",
        mode = "packet-up",
        uplinkHttpMethod = "POST",
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

    private fun kotlinx.coroutines.test.TestScope.controller(
        repositoryFor: ((EndpointId) -> XrayRealityXhttpProfileRepository?)?,
    ) = VpnController(
        FakeVpnTransport(), FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(gateway()),
        FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        xrayRealityXhttpProfileRepositoryFor = repositoryFor,
    )

    @Test
    fun `a stored profile for the endpoint reaches the transport as a Direct REALITY+XHTTP config`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY_XHTTP)
        val controller = controller { id -> if (id == stockholm) FakeRepository(profile) else null }

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY_XHTTP, stockholm))
        runCurrent()

        assertEquals(1, transport.connectCallCount)
        val sent = transport.lastConfig as TransportConfig.XrayRealityXhttp
        assertEquals(profile.toXrayVlessRealityXhttpConfig(), sent.config)
        assertEquals(stockholm, sent.endpointId)
    }

    @Test
    fun `fails closed without touching the transport when nothing is wired, nothing is stored or the endpoint is unknown`() = runTest {
        val cases = listOf<((EndpointId) -> XrayRealityXhttpProfileRepository?)?>(
            null,
            { FakeRepository(null) },
            { id -> if (id == EndpointId("frankfurt")) FakeRepository(profile) else null },
            { FakeRepository(profile.copy(mode = "stream-two")) },
        )
        for (repositoryFor in cases) {
            val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY_XHTTP)
            val controller = controller(repositoryFor)

            controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY_XHTTP, stockholm))
            runCurrent()

            assertEquals(0, transport.connectCallCount)
            assertTrue(controller.state.value is TransportState.Error)
        }
    }
}
