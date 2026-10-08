@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.xray.XrayRuntimeState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

private val XRAY_PROFILE = XrayProfile(
    server = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
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
 * Non-AWG Direct attempts get exactly one ConnectionOutcome from the
 * transport's own observed result, so Auto ranking can learn which
 * REALITY/TLS/Hysteria2 paths work on a network (RU field test).
 */
class VpnControllerStateDrivenOutcomeTest {

    private fun controllerWith(outcomes: FakeConnectionOutcomeStore, scope: kotlinx.coroutines.CoroutineScope) = VpnController(
        FakeVpnTransport(), FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(gateway()),
        FakeReconnectManager(), DiagnosticsStore(), scope,
        xrayProfileRepository = FakeXrayProfileRepository(XRAY_PROFILE),
        connectionOutcomeStore = outcomes,
    )

    @Test
    fun `a confirmed XRAY_REALITY connect records exactly one SUCCESS`() = runTest {
        val outcomes = FakeConnectionOutcomeStore()
        val controller = controllerWith(outcomes, backgroundScope)
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)

        controller.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY))
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        val outcome = outcomes.recent().single()
        assertEquals(TransportKind.XRAY_REALITY, outcome.transport)
        assertEquals(ConnectionOutcomeResult.SUCCESS, outcome.result)
        assertEquals(ConnectionErrorCategory.NONE, outcome.errorCategory)
    }

    @Test
    fun `an XRAY_REALITY remote-confirmation failure records exactly one FAILURE, never a later SUCCESS too`() = runTest {
        val outcomes = FakeConnectionOutcomeStore()
        val controller = controllerWith(outcomes, backgroundScope)
        val xray = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val gate = CompletableDeferred<Unit>()
        xray.connectGate = gate

        backgroundScope.launch { controller.connect(TransportOrchestrator.Resolution.Resolved(xray, TransportKind.XRAY_REALITY)) }
        runCurrent()
        xray.forceState(TransportState.Error("remote handshake not confirmed"))
        runCurrent()
        gate.complete(Unit) // a late Connected from the same attempt must not add a second record
        runCurrent()

        val outcome = outcomes.recent().single()
        assertEquals(ConnectionOutcomeResult.FAILURE, outcome.result)
        assertEquals(ConnectionErrorCategory.HANDSHAKE_TIMEOUT, outcome.errorCategory)
    }

    @Test
    fun `AWG outcomes are unchanged - still exactly one record per attempt`() = runTest {
        val outcomes = FakeConnectionOutcomeStore()
        val controller = controllerWith(outcomes, backgroundScope)

        controller.connect()
        runCurrent()

        val outcome = outcomes.recent().single()
        assertEquals(TransportKind.AMNEZIA_WG, outcome.transport)
        assertEquals(ConnectionOutcomeResult.SUCCESS, outcome.result)
    }

    @Test
    fun `every Xray transport draws session ids from one shared counter`() {
        val a = XrayRuntimeState.nextSessionId()
        val b = XrayRuntimeState.nextSessionId()
        assertNotEquals(a, b)
        assertTrue(b > a)
        // Wall-clock seeded: never the small ids a fresh per-class counter (1, 2, ...) would hand out.
        assertTrue(a > 1_000_000_000_000L)
    }
}
