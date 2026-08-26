@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.AwgClientKeyRepository
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileIdentityStore
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0"),
    profile = AwgProfile.none(),
)

class VpnControllerTest {

    @Test
    fun `missing gateway configuration fails early with a clear message and does not crash`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()

        val state = controller.state.value
        assertTrue(state is TransportState.Error)
        assertTrue((state as TransportState.Error).message.contains("Real VPS required"))
        assertEquals(VpnError.GatewayConfigurationMissing, diagnostics.snapshot.value.lastError)
        assertEquals(0, transport.connectCallCount)
    }

    @Test
    fun `invalid gateway configuration is reported distinctly from missing`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(GatewayConfiguration.Invalid("bad port")),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue(diagnostics.snapshot.value.lastError is VpnError.InvalidGatewayConfiguration)
        assertEquals(0, transport.connectCallCount)
    }

    @Test
    fun `permission required emits an event and does not connect until granted`() = runTest {
        val transport = FakeVpnTransport(permission = android.content.Intent())
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        var requested = false
        val collectJob = backgroundScope.launch {
            controller.events.collect { if (it is ControllerEvent.RequestVpnPermission) requested = true }
        }
        runCurrent() // let the collector actually subscribe before connect() emits

        controller.connect()
        runCurrent()
        assertTrue(requested)
        assertEquals(0, transport.connectCallCount)

        controller.onVpnPermissionResult(true)
        runCurrent()
        assertEquals(1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
        collectJob.cancel()
    }

    @Test
    fun `permission denied returns to a safe error state without connecting`() = runTest {
        val transport = FakeVpnTransport(permission = android.content.Intent())
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        controller.onVpnPermissionResult(false)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(VpnError.PermissionDenied, diagnostics.snapshot.value.lastError)
        assertEquals(0, transport.connectCallCount)
    }

    @Test
    fun `duplicate connect while one is in flight is rejected, not double-started`() = runTest {
        val transport = FakeVpnTransport()
        transport.connectGate = CompletableDeferred()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        val job1 = backgroundScope.launch { controller.connect() }
        runCurrent()
        assertEquals(1, transport.connectCallCount)

        controller.connect() // second call while job1 still holds the mutex
        assertEquals(VpnError.AlreadyInProgress, diagnostics.snapshot.value.lastError)
        assertEquals(1, transport.connectCallCount)

        transport.connectGate!!.complete(Unit)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        job1.cancel()
    }

    @Test
    fun `network loss while connected enters RECONNECTING, and disconnect cancels it permanently`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue("expected Reconnecting, was ${controller.state.value}", controller.state.value is TransportState.Reconnecting)

        controller.disconnect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)

        // User-initiated disconnect must permanently suppress auto-reconnect,
        // even across many backoff intervals.
        advanceTimeBy(120_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.connectCallCount)
    }

    @Test
    fun `network-triggered reconnect eventually reconnects once network returns`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        // Advance past exactly attempt #1's backoff (worst-case jitter), network still down:
        // the loop must back off again (attempt #2) without attempting to reconnect yet.
        val maxJitter = { 1.0 }
        advanceTimeBy(ReconnectBackoff.delayForAttempt(1, maxJitter) + 50)
        runCurrent()
        assertEquals(1, transport.connectCallCount) // still just the original connect - network still down
        assertEquals(TransportState.Reconnecting(2), controller.state.value)

        // Network returns; advance past attempt #2's backoff so the loop's next check sees it.
        reconnectManager.triggerNetworkAvailable()
        advanceTimeBy(ReconnectBackoff.delayForAttempt(2, maxJitter) + 50)
        runCurrent()
        assertEquals(2, transport.connectCallCount)
        assertTrue("expected Connected, was ${controller.state.value}", controller.state.value is TransportState.Connected)
    }

    @Test
    fun `diagnostics never contain the plaintext private key`() = runTest {
        val identityDir = Files.createTempDirectory("vpncontroller-test").toFile()
        val realKeyRepository = AwgClientKeyRepository(FileIdentityStore(identityDir), FakeAesGcmKeyEncryptor())
        val privateKey = realKeyRepository.getPrivateKeyForTunnel()

        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, realKeyRepository,
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertFalse(diagnostics.snapshot.value.toString().contains(privateKey))
        assertFalse(controller.state.value.toString().contains(privateKey))
    }
}
