package net.pocvpn.client.fieldtest

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Always connects with a fresh handshake, or always fails to handshake,
 * depending on [shouldHandshake]. [permissionIntent] defaults to null
 * (already granted) - PR #61 follow-up tests below set it non-null to
 * prove [FieldTestTunnelController] no longer treats that as a reason to
 * fail the candidate (permission gating moved to [FieldTestViewModel]).
 */
private class FixedFieldTestTransport(
    private val shouldHandshake: Boolean,
    private val permissionIntent: Intent? = null,
) : VpnTransport {
    override val name: String = "fixed-field-test"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var disconnectCalled = false
        private set
    var connectCalled = false
        private set

    override fun preparePermissionIntent(): Intent? = permissionIntent
    override suspend fun connect(config: TransportConfig) {
        connectCalled = true
        if (!shouldHandshake) throw RuntimeException("simulated handshake failure")
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() {
        disconnectCalled = true
        stateFlow.value = TransportState.Disconnected
    }
    override fun observeState(): Flow<TransportState> = stateFlow
    override suspend fun stats(): TransportStats =
        if (shouldHandshake) TransportStats.Counters(0, 0, 0L) else TransportStats.Unavailable
}

class FieldTestTunnelControllerTest {

    // Test B - Connect attempts Frankfurt (GERMANY) first, always.
    @Test
    fun `B - connect attempts Frankfurt first`() = runTest {
        val attempted = mutableListOf<ProductionGatewayId>()
        val controller = FieldTestTunnelController(
            transportFactory = { candidate -> attempted += candidate; FixedFieldTestTransport(shouldHandshake = true) },
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        assertEquals(ProductionGatewayId.GERMANY, attempted.first())
    }

    // Test C - Frankfurt failure tries Stockholm.
    @Test
    fun `C - frankfurt failure falls back to Stockholm`() = runTest {
        val attempted = mutableListOf<ProductionGatewayId>()
        val controller = FieldTestTunnelController(
            transportFactory = { candidate ->
                attempted += candidate
                FixedFieldTestTransport(shouldHandshake = candidate == ProductionGatewayId.STOCKHOLM)
            },
            nowProvider = { 0L },
            delayMs = { },
        )
        val result = controller.connect()
        assertEquals(listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), attempted)
        assertTrue(result is FieldTestState.Protected)
        assertEquals(ProductionGatewayId.STOCKHOLM, (result as FieldTestState.Protected).candidate)
    }

    // Test D - successful real transport/data-plane state becomes Protected.
    @Test
    fun `D - fresh handshake plus healthy data-plane check becomes Protected`() = runTest {
        var healthCheckCalled = false
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = true) },
            nowProvider = { 0L },
            delayMs = { },
            healthCheck = { healthCheckCalled = true; true },
        )
        val result = controller.connect()
        assertTrue(result is FieldTestState.Protected)
        assertTrue("health check must run after a fresh handshake, not be skipped", healthCheckCalled)
    }

    // Test D (negative half) - a fresh handshake with a FAILING health check must never become Protected (task's own "do not use fake success based only on transport state").
    @Test
    fun `D - fresh handshake but failed health check never becomes Protected on that candidate`() = runTest {
        val attempted = mutableListOf<ProductionGatewayId>()
        val controller = FieldTestTunnelController(
            transportFactory = { candidate -> attempted += candidate; FixedFieldTestTransport(shouldHandshake = true) },
            nowProvider = { 0L },
            delayMs = { },
            healthCheck = { false },
        )
        val result = controller.connect()
        assertTrue(result is FieldTestState.Failed)
        assertEquals(listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), attempted)
    }

    // Test E - both fail -> Connection failed.
    @Test
    fun `E - both candidates fail, Failed with both attempted`() = runTest {
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = false) },
            nowProvider = { 0L },
            delayMs = { },
        )
        val result = controller.connect()
        assertTrue(result is FieldTestState.Failed)
        assertEquals(listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), (result as FieldTestState.Failed).attempted)
    }

    // A failed candidate's own transport is always torn down before trying the next one / before giving up.
    @Test
    fun `failed candidate transport is disconnected before moving on`() = runTest {
        val transports = mutableListOf<FixedFieldTestTransport>()
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = false).also { transports += it } },
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        assertTrue(transports.all { it.disconnectCalled })
    }

    // Diagnostics requirement - failed Frankfurt attempt is present in diagnostics BEFORE the Stockholm fallback is even attempted.
    @Test
    fun `diagnostics - failed Frankfurt attempt recorded before Stockholm fallback`() = runTest {
        val diagnostics = FieldTestDiagnosticsRecorder(nowProvider = { 0L })
        val controller = FieldTestTunnelController(
            transportFactory = { candidate -> FixedFieldTestTransport(shouldHandshake = candidate == ProductionGatewayId.STOCKHOLM) },
            diagnostics = diagnostics,
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        val events = diagnostics.snapshot()
        val frankfurtResultIndex = events.indexOfFirst {
            it.type == DiagnosticEventType.FIELD_TEST_CANDIDATE_RESULT && it.tags[FieldTestDiagnosticTags.TAG_CANDIDATE] == ProductionGatewayId.GERMANY.name
        }
        val stockholmAttemptIndex = events.indexOfFirst {
            it.type == DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED && it.tags[FieldTestDiagnosticTags.TAG_CANDIDATE] == ProductionGatewayId.STOCKHOLM.name
        }
        assertTrue(frankfurtResultIndex >= 0)
        assertTrue(stockholmAttemptIndex >= 0)
        assertTrue("Frankfurt's own failure must be recorded before Stockholm is ever attempted", frankfurtResultIndex < stockholmAttemptIndex)
        assertEquals("false", events[frankfurtResultIndex].tags[FieldTestDiagnosticTags.TAG_SUCCESS])
    }

    // Diagnostics requirement - a successful Stockholm fallback is present in diagnostics.
    @Test
    fun `diagnostics - successful Stockholm fallback recorded`() = runTest {
        val diagnostics = FieldTestDiagnosticsRecorder(nowProvider = { 0L })
        val controller = FieldTestTunnelController(
            transportFactory = { candidate -> FixedFieldTestTransport(shouldHandshake = candidate == ProductionGatewayId.STOCKHOLM) },
            diagnostics = diagnostics,
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        val events = diagnostics.snapshot()
        assertTrue(
            events.any {
                it.type == DiagnosticEventType.FIELD_TEST_BECAME_PROTECTED &&
                    it.tags[FieldTestDiagnosticTags.TAG_CANDIDATE] == ProductionGatewayId.STOCKHOLM.name
            },
        )
    }

    // Diagnostics requirement - a both-gateway failure is fully recorded (the basis of the local report - see FieldTestViewModelTest for the report itself).
    @Test
    fun `diagnostics - both-gateway failure recorded as unavailable`() = runTest {
        val diagnostics = FieldTestDiagnosticsRecorder(nowProvider = { 0L })
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = false) },
            diagnostics = diagnostics,
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        val events = diagnostics.snapshot()
        val unavailable = events.last()
        assertEquals(DiagnosticEventType.FIELD_TEST_UNAVAILABLE, unavailable.type)
        assertEquals("2", unavailable.tags[FieldTestDiagnosticTags.TAG_ATTEMPTED_COUNT])
    }

    // PR #61 follow-up - the real-device incident's root cause, fixed here:
    // this controller must evaluate a candidate as a genuine transport
    // attempt regardless of what preparePermissionIntent() returns. VPN
    // permission is device/app-level and is FieldTestViewModel's job to
    // resolve BEFORE this controller's connect() is ever called (task
    // requirement 3's own "do not consume a gateway candidate because
    // permission is missing").
    @Test
    fun `permission - a non-null preparePermissionIntent never fails the candidate on its own`() = runTest {
        val permissionIntent = Intent("android.net.VpnService")
        val transport = FixedFieldTestTransport(shouldHandshake = true, permissionIntent = permissionIntent)
        val controller = FieldTestTunnelController(
            transportFactory = { transport },
            nowProvider = { 0L },
            delayMs = { },
        )
        val result = controller.connect()
        assertTrue(
            "a real handshake must still succeed even though preparePermissionIntent() is non-null - permission gating is not this controller's job",
            result is FieldTestState.Protected,
        )
        assertEquals(ProductionGatewayId.GERMANY, (result as FieldTestState.Protected).candidate)
        assertTrue("connect() must actually have been called on the real transport", transport.connectCalled)
    }

    // --- B37: AWG 3.1 generation selection -------------------------------

    // Test A - when wired with FieldTestAwg31GatewayCatalog (the real FieldTestViewModel wiring), diagnostics
    // report AWG_3_1, the isolated port, and the isolated gateway - never the legacy defaults.
    @Test
    fun `B37 A - awg31 gatewayLookup plus awgGeneration records AWG_3_1 with the isolated endpoint-port`() = runTest {
        val diagnostics = FieldTestDiagnosticsRecorder(nowProvider = { 0L })
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = true) },
            diagnostics = diagnostics,
            nowProvider = { 0L },
            delayMs = { },
            gatewayLookup = FieldTestAwg31GatewayCatalog::byId,
            awgGeneration = AwgGeneration.AWG_3_1,
        )
        controller.connect()
        val attempt = diagnostics.snapshot().first { it.type == DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED }
        assertEquals(AwgGeneration.AWG_3_1.name, attempt.tags[FieldTestDiagnosticTags.TAG_AWG_GENERATION])
        assertEquals(FieldTestAwg31GatewayCatalog.FIELD_TEST_PORT.toString(), attempt.tags[FieldTestDiagnosticTags.TAG_ENDPOINT_PORT])
        assertEquals(FieldTestAwg31GatewayCatalog.GERMANY.awg.endpointHost, attempt.tags[FieldTestDiagnosticTags.TAG_ENDPOINT_HOST])
    }

    // Test A (negative half) - the default gatewayLookup/awgGeneration (unchanged pre-B37 behavior) records
    // AWG_LEGACY and the production port - proves the two generations are genuinely distinguishable, not just a label.
    @Test
    fun `B37 A - default wiring (no override) records AWG_LEGACY with the production endpoint-port`() = runTest {
        val diagnostics = FieldTestDiagnosticsRecorder(nowProvider = { 0L })
        val controller = FieldTestTunnelController(
            transportFactory = { FixedFieldTestTransport(shouldHandshake = true) },
            diagnostics = diagnostics,
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        val attempt = diagnostics.snapshot().first { it.type == DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED }
        assertEquals(AwgGeneration.AWG_LEGACY.name, attempt.tags[FieldTestDiagnosticTags.TAG_AWG_GENERATION])
        assertEquals(ProductionGatewayCatalog.GERMANY.awg.endpointPort.toString(), attempt.tags[FieldTestDiagnosticTags.TAG_ENDPOINT_PORT])
    }

    // Test E - a candidate that never produces a fresh handshake is bounded by exactly
    // HANDSHAKE_TIMEOUT_MS / HANDSHAKE_POLL_INTERVAL_MS polls - never an instant fake failure/success.
    @Test
    fun `E - handshake timeout polls a bounded, real number of times before giving up`() = runTest {
        var statsCalls = 0
        val transport = object : VpnTransport {
            override val name = "poll-count-probe"
            override val kind = TransportKind.AMNEZIA_WG
            override val capabilities = TransportCapabilities.amneziaWg()
            override fun preparePermissionIntent(): Intent? = null
            override suspend fun connect(config: TransportConfig) {}
            override suspend fun disconnect() {}
            override fun observeState() = MutableStateFlow<TransportState>(TransportState.Connected)
            override suspend fun stats(): TransportStats {
                statsCalls++
                return TransportStats.Unavailable
            }
        }
        val controller = FieldTestTunnelController(
            transportFactory = { transport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 0L },
            delayMs = { },
        )
        controller.connect()
        val expectedPolls = (FieldTestTunnelController.HANDSHAKE_TIMEOUT_MS / FieldTestTunnelController.HANDSHAKE_POLL_INTERVAL_MS).toInt() + 1
        assertEquals("must poll the full bounded window, never fewer (fake early failure) or more (unbounded)", expectedPolls, statsCalls)
    }
}
