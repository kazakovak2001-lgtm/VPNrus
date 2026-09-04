@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B33 - PR #53's own physical-device follow-up: a real Oppo CPH2173 test
 * found the app reporting Protected/Connected while the actual XRAY_REALITY
 * remote handshake never completed (local Xray process start alone was
 * being treated as sufficient - see XrayCoreControllerTest's own B33 tests
 * for the fix at the source). This file proves the OTHER half of the fix:
 * once a genuine remote-confirmation failure surfaces as a real
 * `TransportState.Error` on the transport's own `observeState()` (exactly
 * what NovaXrayVpnService's new `XrayRuntimeEvent.Failed` publish produces,
 * via the pre-existing, unchanged `xrayTransportStateFor` mapping),
 * [VpnController]'s active-transport collector now records the SAME typed
 * `VpnError.HandshakeTimeout` [AutoGatewayFailoverPolicy] already recognizes
 * as eligible for automatic-gateway advancement for AWG - so a real Xray
 * Direct attempt's terminal failure can finally let the combined Auto
 * sequence move on to the next candidate, exactly like a real AWG handshake
 * timeout already could.
 *
 * Uses [FakeVpnTransport.forceState] to simulate the async
 * Connected/Connecting -> Error transition a real NovaXrayVpnService
 * produces - the same simulation technique [VpnControllerTest]'s own
 * "late/stale emission" tests already use for this exact transport double.
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

private val VALID_XRAY_TLS_PROFILE = XrayTlsProfile(
    server = "152.70.43.1",
    serverPort = 2053,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    serverName = "203.0.113.1",
    fingerprint = "chrome",
)

class VpnControllerXrayFalseProtectedTest {

    @Test
    fun `an async Error from a connected XRAY_REALITY transport records HandshakeTimeout - eligible for Auto advance`() = runTest {
        val realityTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            realityTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(realityTransport, TransportKind.XRAY_REALITY))
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        assertNull("no error should be recorded for a genuine success", diagnostics.snapshot.value.lastError)

        // Simulates NovaXrayVpnService's real async XrayRuntimeEvent.Failed
        // (published only after XrayCoreController.requestStart's own
        // bounded remote-confirmation genuinely failed) reaching this
        // transport's observeState() via the pre-existing, unchanged
        // xrayTransportStateFor mapping.
        realityTransport.forceState(TransportState.Error("remote handshake not confirmed"))
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(VpnError.HandshakeTimeout, diagnostics.snapshot.value.lastError)
        assertTrue(
            "AutoGatewayFailoverPolicy must now treat this as eligible for the next candidate",
            AutoGatewayFailoverPolicy.isEligibleForNextCandidate(controller.state.value, diagnostics.snapshot.value.lastError),
        )
    }

    @Test
    fun `TLS_TCP behaves identically - an async Error records HandshakeTimeout too`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            tlsTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(VALID_XRAY_TLS_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP))
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        tlsTransport.forceState(TransportState.Error("remote handshake not confirmed"))
        runCurrent()

        assertEquals(VpnError.HandshakeTimeout, diagnostics.snapshot.value.lastError)
        assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(controller.state.value, diagnostics.snapshot.value.lastError))
    }

    @Test
    fun `AWG is not regressed - an async Error from an AWG transport never triggers the Xray-specific HandshakeTimeout recording`() = runTest {
        val awgTransport = FakeVpnTransport() // kind defaults to AMNEZIA_WG
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        // An AWG transport reporting a raw Error via its own observeState()
        // (distinct from the real AWG path, which VpnController itself
        // drives via awaitFreshHandshake/HandshakeFailed, never via the
        // transport's own Error state) must NOT be reinterpreted as an Xray
        // remote-confirmation failure - the B33 recording is scoped
        // EXCLUSIVELY to XRAY_REALITY/TLS_TCP kinds.
        awgTransport.forceState(TransportState.Error("unrelated AWG-side error"))
        runCurrent()

        assertNull(
            "AWG's own Error states must never be relabeled as the Xray-specific HandshakeTimeout signal",
            diagnostics.snapshot.value.lastError,
        )
    }

    @Test
    fun `a genuinely successful Xray connection never records any error - no false failure signal`() = runTest {
        val realityTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            realityTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(realityTransport, TransportKind.XRAY_REALITY))
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertFalse(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(controller.state.value, diagnostics.snapshot.value.lastError))
    }
}
