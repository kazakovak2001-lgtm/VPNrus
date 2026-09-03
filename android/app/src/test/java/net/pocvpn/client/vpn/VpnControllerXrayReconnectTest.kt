@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayTlsProfile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B30B - physical-validation fix: a genuine, confirmed total connectivity
 * loss left a real TLS_TCP session showing "Protected" the whole time on a
 * physical Oppo CPH2173 (root cause: [AndroidReconnectManager]'s own docs).
 * [VpnController.handleNetworkLost]/reconnectLoop() were ALREADY kind-
 * agnostic (only ever gated on `_state.value is Connected`, never on
 * `TransportKind` - see that function's updated docs) - what was actually
 * broken was purely the network-loss SIGNAL feeding it. These tests prove
 * the SAME network-loss/recovery behavior [VpnControllerTest]'s existing AWG
 * tests already cover ("network loss while connected enters RECONNECTING...",
 * "network-triggered reconnect eventually reconnects once network returns")
 * holds equally for TLS_TCP and XRAY_REALITY through [FakeReconnectManager] -
 * i.e. this was never an AWG-specific mechanism, so nothing here is a NEW
 * health authority, just proof the EXISTING one already generalizes.
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

class VpnControllerXrayReconnectTest {

    @Test
    fun `TLS_TCP process alive plus underlying network lost eventually leaves Protected`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            tlsTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(VALID_XRAY_TLS_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP))
        runCurrent()
        assertTrue("expected Connected, was ${controller.state.value}", controller.state.value is TransportState.Connected)

        // The Xray process itself never dies here - only the underlying
        // Android network disappears (FakeReconnectManager models exactly
        // that: the transport is untouched, only the network-loss signal
        // fires) - the exact "process alive != tunnel healthy" scenario.
        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(
            "TLS_TCP must leave Protected on a real network loss, was ${controller.state.value}",
            controller.state.value is TransportState.Reconnecting,
        )
    }

    @Test
    fun `TLS_TCP short transient network loss does not immediately fail`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            tlsTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(VALID_XRAY_TLS_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP))
        runCurrent()

        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        // A brief blip - network is back well before MAX_ATTEMPTS could ever
        // exhaust - must recover, never a permanent failure over one
        // transient loss.
        reconnectManager.triggerNetworkAvailable()
        val maxJitter = { 1.0 }
        advanceTimeBy(ReconnectBackoff.delayForAttempt(1, maxJitter) + 50)
        runCurrent()

        assertTrue(
            "a short transient loss must not permanently fail TLS_TCP, was ${controller.state.value}",
            controller.state.value is TransportState.Connected,
        )
        assertEquals(1, tlsTransport.connectCallCount) // recovery never re-calls connect() - same tunnel
    }

    @Test
    fun `TLS_TCP prolonged total loss crosses the bounded health threshold and fails`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            tlsTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(VALID_XRAY_TLS_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP))
        runCurrent()
        reconnectManager.triggerNetworkLost()
        runCurrent()

        // Network never returns - advance past every backoff attempt using
        // the SAME existing ReconnectBackoff constants (no invented timeout).
        val maxJitter = { 1.0 }
        var cumulative = 0L
        for (attempt in 1..(ReconnectBackoff.MAX_ATTEMPTS + 1)) {
            cumulative += ReconnectBackoff.delayForAttempt(attempt, maxJitter)
        }
        advanceTimeBy(cumulative + 1_000)
        runCurrent()

        assertTrue(
            "a prolonged total loss must not remain Protected indefinitely, was ${controller.state.value}",
            controller.state.value is TransportState.Error,
        )
    }

    @Test
    fun `TLS_TCP recovery path can reconnect fresh after an exhausted failure`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val reconnectManager = FakeReconnectManager()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            tlsTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, diagnostics, backgroundScope,
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(VALID_XRAY_TLS_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP))
        runCurrent()
        reconnectManager.triggerNetworkLost()
        runCurrent()

        val maxJitter = { 1.0 }
        var cumulative = 0L
        for (attempt in 1..(ReconnectBackoff.MAX_ATTEMPTS + 1)) {
            cumulative += ReconnectBackoff.delayForAttempt(attempt, maxJitter)
        }
        advanceTimeBy(cumulative + 1_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Error)

        // Network genuinely returns AFTER the session was already marked
        // failed - the existing user/product retry path (a fresh connect())
        // must still work, exactly like the real "tap Connect again" flow.
        // The transport's OWN stateFlow never left Connected during the
        // outage (nothing in the exhaustion path touches it - only this
        // controller's own _state did, via reconnectLoop's direct setState
        // calls), so this second attempt must go through a REAL Connecting
        // transition (gated, so the collector genuinely observes it) rather
        // than relying on a same-value StateFlow conflation to "confirm"
        // recovery - the same discipline production's real async Xray
        // startup naturally has (real I/O between Connecting and Connected,
        // never synchronous).
        reconnectManager.triggerNetworkAvailable()
        tlsTransport.connectGate = kotlinx.coroutines.CompletableDeferred()
        val secondConnect = launch { controller.connect(TransportOrchestrator.Resolution.Resolved(tlsTransport, TransportKind.TLS_TCP)) }
        runCurrent()
        assertTrue(
            "expected Connecting mid-attempt, was ${controller.state.value}",
            controller.state.value is TransportState.Connecting,
        )
        tlsTransport.connectGate?.complete(Unit)
        runCurrent()
        secondConnect.join()

        assertEquals(2, tlsTransport.connectCallCount)
        assertTrue("expected Connected, was ${controller.state.value}", controller.state.value is TransportState.Connected)
    }

    @Test
    fun `XRAY_REALITY is not regressed - network loss and recovery behave the same as TLS_TCP`() = runTest {
        val realityTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            realityTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(VALID_XRAY_PROFILE),
        )

        controller.connect(TransportOrchestrator.Resolution.Resolved(realityTransport, TransportKind.XRAY_REALITY))
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(
            "XRAY_REALITY must also leave Protected on a real network loss, was ${controller.state.value}",
            controller.state.value is TransportState.Reconnecting,
        )

        reconnectManager.triggerNetworkAvailable()
        val maxJitter = { 1.0 }
        advanceTimeBy(ReconnectBackoff.delayForAttempt(1, maxJitter) + 50)
        runCurrent()
        assertTrue(
            "XRAY_REALITY must recover once network returns, was ${controller.state.value}",
            controller.state.value is TransportState.Connected,
        )
    }

    @Test
    fun `AWG is not regressed by ReconnectManager fix - still only one reconnect authority engages`() = runTest {
        val transport = FakeVpnTransport() // kind defaults to AMNEZIA_WG
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)

        reconnectManager.triggerNetworkLost()
        runCurrent()
        // Exactly one reconnectManager.start() call for this controller's
        // whole lifetime (its own init{} block) - no second/duplicate health
        // authority was introduced alongside it.
        assertEquals(1, reconnectManager.startCallCount)
        assertTrue(controller.state.value is TransportState.Reconnecting)
    }
}
