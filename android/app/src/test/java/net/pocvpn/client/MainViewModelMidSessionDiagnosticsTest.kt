@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.DiagnosticOutcome
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeConnectionOutcomeStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.ReconnectBackoff
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B30C - the fix: B29's own session for the initial attempt closes as
 * PROTECTED the moment the VPN first reaches Protected (see
 * SupportDiagnosticsRecorder.finishProtected's own docs), so a LATER real
 * reconnect incident on an already-protected session had no open session to
 * record into at all (finishFailed()'s own "open ?: return" guard silently
 * dropped it). These tests prove the fix end-to-end through the REAL
 * MainViewModel/VpnController/ReconnectManager path (not the isolated
 * recorder) - the same FakeReconnectManager double
 * [net.pocvpn.client.vpn.VpnControllerXrayReconnectTest] already uses to
 * drive a real reconnect incident.
 */
class MainViewModelMidSessionDiagnosticsTest {

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private val configuredGateway = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10",
        endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2",
        gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0", "::/0"),
        profile = AwgProfile.none(),
    )

    private val usableWifi = NetworkProfile(
        type = NetworkType.WIFI, validatedInternet = true, metered = false,
        roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
        vpnActive = false, generation = 1,
    )

    private fun newViewModel(
        store: InMemoryDiagnosticSessionStore,
        transport: FakeVpnTransport,
        reconnectManager: FakeReconnectManager,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
        reconnectManager = reconnectManager,
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        initialNetworkProfile = usableWifi,
        connectionOutcomeStore = FakeConnectionOutcomeStore(),
        supportDiagnosticsRecorder = SupportDiagnosticsRecorder(store, appVersionName = "1.0", appVersionCode = 1L),
        supportDiagnosticsStore = store,
        supportDiagnosticsAppVersionName = "1.0",
        supportDiagnosticsAppVersionCode = 1L,
    )

    private fun exhaustReconnect() {
        val maxJitter = { 1.0 }
        var cumulative = 0L
        for (attempt in 1..(ReconnectBackoff.MAX_ATTEMPTS + 1)) {
            cumulative += ReconnectBackoff.delayForAttempt(attempt, maxJitter)
        }
        testDispatcher.scheduler.advanceTimeBy(cumulative + 1_000)
        testDispatcher.scheduler.runCurrent()
    }

    @Test
    fun `initial connect closes the original session as PROTECTED, and ordinary steady state creates no more`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val viewModel = newViewModel(store, FakeVpnTransport(), reconnectManager)
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, store.recent().size)
        assertEquals(DiagnosticOutcome.PROTECTED, store.recent().single().outcome)

        // No network event at all - steady state must never grow the store.
        testDispatcher.scheduler.advanceTimeBy(5_000)
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, store.recent().size)
    }

    @Test
    fun `later Protected to Reconnecting opens exactly one new incident session, never one per retry`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val viewModel = newViewModel(store, FakeVpnTransport(), reconnectManager)
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, store.recent().size)

        reconnectManager.triggerNetworkLost()
        testDispatcher.scheduler.runCurrent()

        // Multiple backoff attempts fire while the network stays unavailable
        // - still exactly one NEW open incident session, never a second one
        // per attempt.
        testDispatcher.scheduler.advanceTimeBy(ReconnectBackoff.delayForAttempt(1) + ReconnectBackoff.delayForAttempt(2) + ReconnectBackoff.delayForAttempt(3) + 200)
        testDispatcher.scheduler.runCurrent()

        assertEquals("original session must not be reopened/mutated", 1, store.recent().count { it.outcome == DiagnosticOutcome.PROTECTED })
        assertEquals("exactly one open incident, not yet closed", 1, store.recent().size)
    }

    @Test
    fun `reconnect success closes the incident session as PROTECTED, distinct from the original`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val viewModel = newViewModel(store, FakeVpnTransport(), reconnectManager)
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        val originalSessionId = store.recent().single().sessionId

        reconnectManager.triggerNetworkLost()
        testDispatcher.scheduler.runCurrent()
        reconnectManager.triggerNetworkAvailable()
        testDispatcher.scheduler.advanceTimeBy(ReconnectBackoff.delayForAttempt(1) + 200)
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, store.recent().size)
        val incident = store.recent().first { it.sessionId != originalSessionId }
        assertEquals(DiagnosticOutcome.PROTECTED, incident.outcome)
        assertTrue(incident.events.any { it.type == DiagnosticEventType.RECONNECT_INCIDENT_STARTED })
        val original = store.recent().first { it.sessionId == originalSessionId }
        assertEquals(DiagnosticOutcome.PROTECTED, original.outcome)
    }

    @Test
    fun `reconnect exhaustion closes the incident session as FAILED`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val viewModel = newViewModel(store, FakeVpnTransport(), reconnectManager)
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        val originalSessionId = store.recent().single().sessionId

        reconnectManager.triggerNetworkLost()
        testDispatcher.scheduler.runCurrent()
        exhaustReconnect()

        assertEquals(2, store.recent().size)
        val incident = store.recent().first { it.sessionId != originalSessionId }
        assertEquals(DiagnosticOutcome.FAILED, incident.outcome)
        assertTrue(incident.events.any { it.type == DiagnosticEventType.RECONNECT_INCIDENT_STARTED })
    }

    @Test
    fun `manual retry after terminal failure opens exactly one new attempt session`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val transport = FakeVpnTransport()
        val viewModel = newViewModel(store, transport, reconnectManager)
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        reconnectManager.triggerNetworkLost()
        testDispatcher.scheduler.runCurrent()
        exhaustReconnect()
        assertEquals(2, store.recent().size) // original PROTECTED + failed incident

        reconnectManager.networkAvailable = true
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(3, store.recent().size)
        assertEquals(DiagnosticOutcome.PROTECTED, store.recent().first().outcome)
    }

    @Test
    fun `manual disconnect mid-reconnect closes the incident as DISCONNECTED and leaves nothing dangling`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val viewModel = newViewModel(store, FakeVpnTransport(), reconnectManager)
        testDispatcher.scheduler.runCurrent()
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        val originalSessionId = store.recent().single().sessionId

        reconnectManager.triggerNetworkLost()
        testDispatcher.scheduler.runCurrent()

        viewModel.disconnect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, store.recent().size)
        val incident = store.recent().first { it.sessionId != originalSessionId }
        assertEquals(DiagnosticOutcome.DISCONNECTED, incident.outcome)
    }

    @Test
    fun `support-bundle retention still keeps only the last 8 sessions across original plus incident sessions`() = runTest {
        val store = InMemoryDiagnosticSessionStore()
        val reconnectManager = FakeReconnectManager()
        val transport = FakeVpnTransport()
        val viewModel = newViewModel(store, transport, reconnectManager)
        testDispatcher.scheduler.runCurrent()

        // 5 connect/incident-exhaust/retry cycles = 10 sessions produced,
        // only the last 8 (InMemoryDiagnosticSessionStore.MAX_RETAINED_SESSIONS) survive.
        repeat(5) {
            reconnectManager.networkAvailable = true
            viewModel.connect()
            testDispatcher.scheduler.runCurrent()
            reconnectManager.triggerNetworkLost()
            testDispatcher.scheduler.runCurrent()
            exhaustReconnect()
        }

        assertEquals(8, store.recent().size)
    }
}
