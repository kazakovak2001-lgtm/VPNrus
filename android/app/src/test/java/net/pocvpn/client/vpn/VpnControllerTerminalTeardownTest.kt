@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B34 - physically reproduced as a real bug (PR #53's own CHAIN_DIRECT
 * physical validation, 2026-09-04): once the combined Auto sequence
 * genuinely exhausted every admitted candidate, `MainViewModel.attemptCombined`
 * reported the terminal error via `VpnController.rejectPreflight` - a
 * function built for "reject before this controller was ever touched" (see
 * its own docs) that never tears down a transport/tun a REAL prior attempt
 * in this same sequence already brought up. On the physical device this
 * left a stale, non-functional VPN interface installed and NO working
 * Internet at all until the app process was force-stopped - worse than the
 * "Connection failed" UI communicated.
 *
 * These tests exercise [VpnController.abandonAttemptWithTerminalError]
 * directly - the real fix - proving it tears down the active transport
 * exactly once, ends at a genuine terminal [TransportState.Error] (never a
 * plain [TransportState.Disconnected] the UI/diagnostics could mistake for
 * an ordinary user-initiated stop - task's own "do not silently report
 * normal Disconnected instead"), and leaves the controller in a genuinely
 * clean state for a subsequent real connect() to start from.
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0"),
    profile = AwgProfile.none(),
)

class VpnControllerTerminalTeardownTest {

    // --- 1/4/5: terminal exhaustion produces a real, visible, non-Connected terminal error ---

    @Test
    fun `final candidate fails - abandonAttemptWithTerminalError produces the exact terminal error, never a stale Connected state`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
                server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
            )),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        controller.abandonAttemptWithTerminalError(VpnError.NoCandidateAvailable, "Automatic gateway candidates exhausted")
        runCurrent()

        val state = controller.state.value
        assertTrue("expected a terminal Error, was $state", state is TransportState.Error)
        assertEquals("Automatic gateway candidates exhausted", (state as TransportState.Error).message)
        assertEquals(VpnError.NoCandidateAvailable, diagnostics.snapshot.value.lastError)
    }

    // --- 2: the active transport receives exactly one teardown ---

    @Test
    fun `the active transport is torn down exactly once`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
                server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
            )),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()
        assertEquals(0, transport.disconnectCallCount)

        controller.abandonAttemptWithTerminalError(VpnError.NoCandidateAvailable, "Automatic gateway candidates exhausted")
        runCurrent()

        // 3 - this IS the VpnService/tun release boundary this codebase's
        // own VpnTransport abstraction owns (see disconnect()'s own real
        // NovaXrayVpnService.ACTION_STOP path) - the same level every other
        // teardown assertion in this suite is made at.
        assertEquals(1, transport.disconnectCallCount)
    }

    // --- 6: a subsequent real connect() starts from a genuinely clean lifecycle ---

    @Test
    fun `a later user-initiated connect after terminal exhaustion starts cleanly and can genuinely reach Connected`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
                server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
            )),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()
        controller.abandonAttemptWithTerminalError(VpnError.NoCandidateAvailable, "Automatic gateway candidates exhausted")
        runCurrent()
        assertTrue(controller.state.value is TransportState.Error)

        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertTrue(
            "a fresh connect() must be genuinely accepted, not swallowed by a stale Connecting/Connected guard",
            controller.state.value is TransportState.Connected,
        )
        assertEquals(2, transport.connectCallCount)
    }

    // --- 7: AWG terminal exhaustion gets equivalent cleanup ---

    @Test
    fun `AWG terminal exhaustion also tears down the transport and preserves the terminal error`() = runTest {
        val transport = FakeVpnTransport() // kind defaults to AMNEZIA_WG
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )
        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        controller.abandonAttemptWithTerminalError(VpnError.NoCandidateAvailable, "Automatic gateway candidates exhausted")
        runCurrent()

        assertEquals(1, transport.disconnectCallCount)
        val state = controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals("Automatic gateway candidates exhausted", (state as TransportState.Error).message)
    }

    // --- 8: manual disconnect semantics are unchanged (still ends at plain Disconnected, still sets userInitiatedDisconnect) ---

    @Test
    fun `manual disconnect is unaffected by the new terminal-error teardown path - still ends at plain Disconnected`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )
        controller.connect()
        runCurrent()

        controller.disconnect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.disconnectCallCount)
    }

    // --- abandonAttemptForFailover's own pre-existing behavior is unaffected by sharing the new extracted teardown helper ---

    @Test
    fun `abandonAttemptForFailover still ends at plain Disconnected - unaffected by the shared teardown extraction, and never records an error itself`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
                server = "152.70.43.1", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
                flow = "xtls-rprx-vision", serverName = "www.microsoft.com", fingerprint = "chrome",
                realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
            )),
        )
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.XRAY_REALITY))
        runCurrent()

        controller.abandonAttemptForFailover()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Disconnected)
        assertEquals(1, transport.disconnectCallCount)
        assertEquals("abandonAttemptForFailover must never record a terminal error itself", null, diagnostics.snapshot.value.lastError)
    }
}
