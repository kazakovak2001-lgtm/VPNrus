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
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.TransportConfig
import net.pocvpn.client.vpn.xray.toXrayVlessRealityConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

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
        // B8G: the explicit user disconnect is what actually tore the
        // session down - the only transport.disconnect() call anywhere in
        // this whole scenario.
        assertEquals(1, transport.disconnectCallCount)

        // User-initiated disconnect must permanently suppress auto-reconnect,
        // even across many backoff intervals.
        advanceTimeBy(120_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.connectCallCount)
        assertEquals(1, transport.disconnectCallCount)
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
        // B8G1: recovery never re-calls transport.connect() - the SAME
        // established tunnel is just polled for a fresh handshake (see
        // VpnController.reconnectLoop's own docs) - connectCallCount stays
        // at the original 1 throughout this whole scenario.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
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

    // --- B8I4: per-attempt execution boundary - connect(resolved) ---

    @Test
    fun `an explicit AWG resolution executes through the SAME per-attempt boundary as the default connect()`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG))
        runCurrent()

        // Proves the resolved instance really is what got invoked, not merely
        // that "some" connect happened.
        assertEquals(1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `a resolution naming a non-AWG kind is refused even for this controller's own transport instance`() = runTest {
        val transport = FakeVpnTransport() // this instance's own .kind is AMNEZIA_WG
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        // A resolution whose kind disagrees with the kind buildTransportConfig()
        // can actually build for - must fail closed even though the transport
        // INSTANCE itself is the one this controller owns.
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
        assertTrue(diagnostics.snapshot.value.lastError is VpnError.UnsupportedTransportSelected)
    }

    @Test
    fun `permission flow still works through an explicit resolution and resumes with the SAME resolved kind after grant`() = runTest {
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
        runCurrent()

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG))
        runCurrent()
        assertTrue(requested)
        assertEquals(0, transport.connectCallCount)

        controller.onVpnPermissionResult(true)
        runCurrent()
        assertEquals(1, transport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
        collectJob.cancel()
    }

    // --- B8I5: active transport ownership - connect() can adopt a genuinely different resolved instance ---

    @Test
    fun `connect adopts a different resolved AWG transport instance as the active transport - never the constructor-owned one`() = runTest {
        val constructedTransport = FakeVpnTransport()
        val resolvedTransport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            constructedTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(resolvedTransport, TransportKind.AMNEZIA_WG))
        runCurrent()

        // The RESOLVED instance is what actually ran - the constructor-owned
        // one (never selected for this attempt) is completely untouched.
        assertEquals(1, resolvedTransport.connectCallCount)
        assertEquals(0, constructedTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `switching active transport stops observing the previous one - stale emissions never leak into controller state`() = runTest {
        val transportA = FakeVpnTransport()
        val transportB = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transportA, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect() // default resolves to transportA
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        controller.disconnect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Disconnected)

        controller.connect(TransportOrchestrator.Resolution.Resolved(transportB, TransportKind.AMNEZIA_WG))
        runCurrent()
        assertEquals(1, transportB.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)

        // transportA's collector was detached on switch - a late/stale
        // emission from it must never overwrite the CURRENT (transportB)
        // state. No two collectors can ever drive _state concurrently.
        transportA.forceState(TransportState.Error("stale from detached transport"))
        runCurrent()
        assertTrue(
            "stale emission from a detached transport leaked into controller state: ${controller.state.value}",
            controller.state.value is TransportState.Connected,
        )
    }

    @Test
    fun `permission grant resumes the SAME resolved non-constructor transport instance after switching`() = runTest {
        val constructedTransport = FakeVpnTransport()
        val resolvedTransport = FakeVpnTransport(permission = android.content.Intent())
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            constructedTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(resolvedTransport, TransportKind.AMNEZIA_WG))
        runCurrent()
        assertEquals(0, resolvedTransport.connectCallCount)
        assertEquals(0, constructedTransport.connectCallCount)

        controller.onVpnPermissionResult(true)
        runCurrent()

        // Both the resolved INSTANCE and its kind survived the permission
        // round-trip - the constructor-owned transport is never touched.
        assertEquals(1, resolvedTransport.connectCallCount)
        assertEquals(0, constructedTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `shutdown detaches the active transport's observer - later emissions never reach controller state`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        controller.shutdown()
        runCurrent()
        assertEquals(1, reconnectManager.stopCallCount)

        transport.forceState(TransportState.Error("late emission after shutdown"))
        runCurrent()
        assertTrue(
            "emission after shutdown leaked into controller state: ${controller.state.value}",
            controller.state.value is TransportState.Connected,
        )
    }

    // --- B8I6: real Xray executable wiring ---

    @Test
    fun `resolved XRAY_REALITY with a valid stored profile invokes the exact Xray transport with the real Xray config`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(0, awgTransport.connectCallCount) // the constructor-owned AWG transport is never touched
        val sentConfig = xrayTransport.lastConfig
        assertTrue(sentConfig is TransportConfig.Xray)
        // Built from the REAL persisted profile - never fabricated from AWG GatewayConfiguration fields.
        assertEquals(VALID_XRAY_PROFILE.toXrayVlessRealityConfig(), (sentConfig as TransportConfig.Xray).config)
    }

    @Test
    fun `a missing Xray profile fails closed before the Xray transport is ever touched`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(profile = null)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(VpnError.ConfigurationMappingFailure("XrayProfileNotReadyException"), diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `an invalid stored Xray profile fails closed before the Xray transport is ever touched`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE.copy(uuid = "not-a-uuid"))
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(VpnError.ConfigurationMappingFailure("XrayProfileNotReadyException"), diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `AWG behavior is unchanged when a VpnController is also wired with an Xray profile repository`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        controller.connect() // default -> AWG, exactly as every pre-B8I6 test exercises
        runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertTrue(awgTransport.lastConfig is TransportConfig.Awg)
        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `Xray permission flow, permission resume, and disconnect all target the active Xray transport - never the constructor-owned AWG one`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY, permission = android.content.Intent())
        val xrayRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        var requested = false
        val collectJob = backgroundScope.launch {
            controller.events.collect { if (it is ControllerEvent.RequestVpnPermission) requested = true }
        }
        runCurrent()

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()
        assertTrue(requested)
        assertEquals(0, xrayTransport.connectCallCount)
        assertEquals(0, awgTransport.connectCallCount)

        controller.onVpnPermissionResult(true)
        runCurrent()
        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(0, awgTransport.connectCallCount)

        controller.disconnect()
        runCurrent()
        assertEquals(1, xrayTransport.disconnectCallCount)
        assertEquals(0, awgTransport.disconnectCallCount)
        collectJob.cancel()
    }

    @Test
    fun `no Xray profile secret field ever appears in diagnostics or controller state text`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val invalidProfile = VALID_XRAY_PROFILE.copy(uuid = "not-a-uuid")
        val xrayRepository = FakeXrayProfileRepository(invalidProfile)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = xrayRepository,
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertFalse(diagnostics.snapshot.value.toString().contains(invalidProfile.realityPublicKey))
        assertFalse(diagnostics.snapshot.value.toString().contains(invalidProfile.shortId))
        assertFalse(controller.state.value.toString().contains(invalidProfile.realityPublicKey))
        assertFalse(controller.state.value.toString().contains(invalidProfile.shortId))
    }
}
