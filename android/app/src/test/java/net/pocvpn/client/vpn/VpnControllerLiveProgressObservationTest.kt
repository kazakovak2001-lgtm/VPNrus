@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.smartconnect.AttemptStageOutcome
import net.pocvpn.client.smartconnect.AttemptTermination
import net.pocvpn.client.smartconnect.TrafficProgressOutcome
import net.pocvpn.client.smartconnect.TransportAttemptProtocol
import net.pocvpn.client.smartconnect.TransportObservationStore
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL7 - proves the live traffic-progress sampler VpnController wires into
 * its existing AmneziaWG handshake-success lifecycle point
 * (launchLiveProgressObservation) actually turns real TransportStats.Counters
 * samples into the right TransportAttemptObservation, is bounded, never
 * fabricates evidence a fake transport did not provide, and never lets a
 * superseded attempt record stale evidence.
 */
private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val fakeUsableNetworkProfile = NetworkProfile(
    type = NetworkType.WIFI,
    validatedInternet = true,
    metered = false,
    roaming = false,
    captivePortal = false,
    ipv4Available = true,
    ipv6Available = false,
    vpnActive = false,
    generation = 1,
    dnsServerAddresses = listOf("1.1.1.1"),
)

class VpnControllerLiveProgressObservationTest {

    private fun newController(
        transport: FakeVpnTransport,
        store: TransportObservationStore?,
        scope: kotlinx.coroutines.CoroutineScope,
        reconnectManager: FakeReconnectManager = FakeReconnectManager(),
    ) = VpnController(
        transport, FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager, DiagnosticsStore(), scope,
        transportObservationStore = store,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        networkProfileProvider = { fakeUsableNetworkProfile },
    )

    private fun fingerprint() = NetworkFingerprinter.fingerprint(
        CoarseNetworkSignals(fakeUsableNetworkProfile.type, fakeUsableNetworkProfile.dnsServerAddresses),
        byteArrayOf(1, 2, 3, 4),
    )

    @Test
    fun `sustained receive progress across the verification window yields SUSTAINED progress`() = runTest {
        val transport = FakeVpnTransport()
        var calls = 0
        transport.statsProvider = {
            calls++
            TransportStats.Counters(bytesReceived = calls * 100L, bytesSent = calls * 50L, lastHandshakeEpochMillis = System.currentTimeMillis())
        }
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(11_000)
        runCurrent()

        val observation = store.recent(fingerprint()).single()
        assertEquals(TrafficProgressOutcome.SUSTAINED, observation.progress)
        assertEquals(AttemptStageOutcome.SUCCEEDED, observation.connect)
        assertEquals(AttemptStageOutcome.SUCCEEDED, observation.handshake)
        assertTrue(observation.bytesReceived > 0)
    }

    @Test
    fun `initial payload followed by a bounded stall yields STALLED_AFTER_INITIAL_PAYLOAD`() = runTest {
        val transport = FakeVpnTransport()
        var calls = 0
        transport.statsProvider = {
            calls++
            // One real payload up front, then silence while we keep sending -
            // never inferred as a stall without outbound demand (see
            // TrafficProgressMonitor's own docs).
            TransportStats.Counters(bytesReceived = 100L, bytesSent = calls * 50L, lastHandshakeEpochMillis = System.currentTimeMillis())
        }
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(21_000)
        runCurrent()

        val observation = store.recent(fingerprint()).single()
        assertEquals(TrafficProgressOutcome.STALLED_AFTER_INITIAL_PAYLOAD, observation.progress)
        assertEquals(AttemptTermination.NONE_OBSERVED, observation.termination)
    }

    @Test
    fun `no outbound demand and no payload is recorded as NOT_OBSERVED, never a fabricated failure`() = runTest {
        val transport = FakeVpnTransport() // flat (0, 0) counters forever
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(30_001)
        runCurrent()

        val observation = store.recent(fingerprint()).single()
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, observation.progress)
        assertEquals(AttemptStageOutcome.SUCCEEDED, observation.connect)
    }

    @Test
    fun `a transport with no real counters at all is recorded NOT_OBSERVED immediately, never fabricated`() = runTest {
        val transport = FakeVpnTransport()
        transport.statsProvider = { TransportStats.Unsupported }
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent() // no advanceTimeBy - must not need the bounded window at all

        val observation = store.recent(fingerprint()).single()
        assertEquals(TrafficProgressOutcome.NOT_OBSERVED, observation.progress)
        assertEquals(0L, observation.bytesReceived)
    }

    @Test
    fun `protocol is decided by the transport's real capabilities, never by TransportKind`() = runTest {
        // Deliberately AMNEZIA_WG kind with TCP-only capabilities - proves the
        // writer reads capabilities.usesUdp, never a hardcoded kind branch.
        val transport = FakeVpnTransport(capabilitiesOverride = TransportCapabilities.xrayRealityAdapterShell())
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(30_001)
        runCurrent()

        val observation = store.recent(fingerprint()).single()
        assertEquals(TransportAttemptProtocol.TCP, observation.protocol)
    }

    @Test
    fun `a new connect attempt cancels a still-running sampler - no duplicate or stale recording`() = runTest {
        val transport = FakeVpnTransport() // flat (0, 0) - sampler would otherwise run the full 30s window
        val store = TransportObservationStore()
        val controller = newController(transport, store, backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(5_000) // well inside the bounded window - sampler still running
        runCurrent()
        assertTrue(store.recent(fingerprint()).isEmpty())

        controller.disconnect()
        runCurrent()
        controller.connect()
        runCurrent()
        advanceTimeBy(30_001)
        runCurrent()

        // Exactly one observation for the SECOND attempt - the first
        // sampler's job was cancelled, never raced a second write in.
        assertEquals(1, store.recent(fingerprint()).size)
    }

    @Test
    fun `an automatic network-loss reconnect cancels the still-running sampler - no stale evidence from the outage`() = runTest {
        val transport = FakeVpnTransport() // flat (0, 0) - sampler would otherwise reach IDLE at 20s
        val store = TransportObservationStore()
        val reconnectManager = FakeReconnectManager()
        val controller = newController(transport, store, backgroundScope, reconnectManager)

        controller.connect()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        advanceTimeBy(1_000) // sampler is running, well before its 20s decisive point
        runCurrent()

        // B-WL7 review fix - handleNetworkLost() -> startReconnect() must
        // cancel the STILL-RUNNING sampler from the attempt just superseded,
        // exactly like disconnect()/a new connect() already do.
        reconnectManager.triggerNetworkLost()
        runCurrent()

        // Network never comes back in this test, so reconnectLoop just backs
        // off (never reaches awaitFreshHandshake/records its own outcome) -
        // well past the 20s the ORIGINAL sampler needed to conclude IDLE and
        // write, but nothing is ever recorded, because that sampler was
        // cancelled instead of running to completion against a transport
        // that is no longer part of a valid session.
        advanceTimeBy(30_001)
        runCurrent()

        assertTrue(store.recent(fingerprint()).isEmpty())
    }

    // --- dead data plane behind a live AWG handshake (RU field test CONNECTED_NO_DATA) ---

    private suspend fun kotlinx.coroutines.test.TestScope.connectWith(
        stats: (Int) -> TransportStats,
        store: TransportObservationStore? = TransportObservationStore(),
    ): Triple<VpnController, FakeVpnTransport, DiagnosticsStore> {
        val transport = FakeVpnTransport()
        var calls = 0
        transport.statsProvider = { calls++; stats(calls) }
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            transportObservationStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )
        controller.connect()
        runCurrent()
        return Triple(controller, transport, diagnostics)
    }

    @Test
    fun `sending with nothing coming back ends the session with DataPlaneNoTraffic instead of a false Protected`() = runTest {
        val (controller, transport, diagnostics) = connectWith({ n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) })
        assertTrue(controller.state.value is TransportState.Connected)

        advanceTimeBy(31_000)
        runCurrent()

        val state = controller.state.value
        assertTrue(state is TransportState.Error)
        assertEquals(TransportFailureKind.REMOTE_UNCONFIRMED, (state as TransportState.Error).failureKind)
        assertEquals(net.pocvpn.client.diagnostics.VpnError.DataPlaneNoTraffic, diagnostics.snapshot.value.lastError)
        assertTrue(transport.disconnectCallCount >= 1)
    }

    @Test
    fun `an early-drop stall after initial payload also ends the session`() = runTest {
        val (controller, _, diagnostics) = connectWith({ n -> TransportStats.Counters(bytesReceived = 100L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) })

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(net.pocvpn.client.diagnostics.VpnError.DataPlaneNoTraffic, diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `the dead data plane is acted on even without an observation store`() = runTest {
        val (controller, _, _) = connectWith({ n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) }, store = null)

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
    }

    @Test
    fun `a working or idle session is never torn down by the progress check`() = runTest {
        val (working, workingTransport, _) = connectWith({ n -> TransportStats.Counters(bytesReceived = n * 100L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) })
        val (idle, _, _) = connectWith({ _ -> TransportStats.Counters(bytesReceived = 0L, bytesSent = 0L, lastHandshakeEpochMillis = System.currentTimeMillis()) })

        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(working.state.value is TransportState.Connected)
        assertTrue(idle.state.value is TransportState.Connected)
        assertEquals(0, workingTransport.disconnectCallCount)
    }

    @Test
    fun `a user disconnect during the window wins - no late Error`() = runTest {
        val (controller, _, _) = connectWith({ n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) })
        advanceTimeBy(5_000)
        runCurrent()

        controller.disconnect()
        runCurrent()
        advanceTimeBy(31_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Disconnected)
    }

    // --- stale observer vs automatic reconnect: ownership-generation fix ---

    /**
     * Builds the same AWG session shape [connectWith] does, but also
     * returns the real [FakeReconnectManager] so a test can drive an
     * automatic network-loss reconnect directly.
     */
    private suspend fun kotlinx.coroutines.test.TestScope.connectWithReconnectManager(
        stats: (Int) -> TransportStats,
    ): Pair<VpnController, FakeVpnTransport> {
        val transport = FakeVpnTransport()
        var calls = 0
        transport.statsProvider = { calls++; stats(calls) }
        val reconnectManager = FakeReconnectManager()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            transportObservationStore = null,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )
        controller.connect()
        runCurrent()
        reconnectManagerForLastController = reconnectManager
        return controller to transport
    }

    private var reconnectManagerForLastController: FakeReconnectManager? = null

    /**
     * Integration-level reproduction of the end-to-end scenario: a stale
     * observer reaches its decisive NO_PAYLOAD verdict and self-detaches,
     * then genuinely suspends trying to acquire connectMutex (held by this
     * test via holdConnectMutexForTest - no arbitrary sleep). A real
     * automatic network-loss reconnect is triggered while it waits. In this
     * exact interleaving, reconnectLoop's own state transition to
     * Reconnecting typically runs (on the test dispatcher's enqueue order)
     * before the queued observer resumes, so the pre-existing _state guard
     * alone may already be what rejects the observer here - this test does
     * NOT by itself isolate or prove the new reconnect-generation guard is
     * necessary (see the next test, which is built specifically to do
     * that). What this test does verify end-to-end is that the overall
     * outcome is correct and safe: whichever guard actually fires, the
     * stale observer must back off instead of tearing the session down or
     * overwriting the reconnect's state, and the automatic reconnect must
     * be left to proceed normally into Reconnecting.
     */
    @Test
    fun `integration - a stale observer queued on connectMutex does not undo an automatic reconnect that already took ownership`() = runTest {
        val (controller, transport) = connectWithReconnectManager { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) }
        val reconnectManager = reconnectManagerForLastController!!
        assertTrue(controller.state.value is TransportState.Connected)

        val release = CompletableDeferred<Unit>()
        backgroundScope.launch { controller.holdConnectMutexForTest(release) }
        runCurrent()

        // Advance the sampler to its decisive NO_PAYLOAD verdict. It self-
        // detaches, then suspends acquiring connectMutex - held above.
        advanceTimeBy(31_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(0, transport.disconnectCallCount)

        // A real automatic network-loss reconnect begins WHILE the stale
        // observer is queued on the mutex it no longer has authority over.
        reconnectManager.triggerNetworkLost()

        release.complete(Unit)
        runCurrent()

        val stateAfterRelease = controller.state.value
        assertTrue(
            "a stale NO_PAYLOAD verdict sampled before the outage must never " +
                "produce a terminal Error for a session an automatic reconnect " +
                "already owns - saw $stateAfterRelease",
            stateAfterRelease !is TransportState.Error,
        )
        assertTrue(
            "the automatic reconnect must have been left to proceed into " +
                "Reconnecting, not silently stuck in some other non-Error state " +
                "- saw $stateAfterRelease",
            stateAfterRelease is TransportState.Reconnecting,
        )
        assertEquals(
            "the stale observer must not have disconnected the transport the reconnect still owns",
            0,
            transport.disconnectCallCount,
        )
    }

    /**
     * Isolates the NEW ownership check from the pre-existing _state/
     * activeTransport one, using a path that provably never touches either:
     * a second explicit [VpnController.connect] call, superseding an
     * already-started (but not yet dispatched) reconnect, cancels that
     * reconnectJob BEFORE it is ever resumed for the first time - which
     * means reconnectLoop's body (the only code that would move _state to
     * Reconnecting) never runs at all - then itself queues on the same held
     * connectMutex. [Mutex] is documented to hand the lock to waiters in
     * strict FIFO order, so when the mutex is released, the stale observer -
     * parked first, well before this second connect() call ever asked for
     * it - is guaranteed to run its ownership check first, not as an
     * artifact of this test's dispatcher happening to pick that order. At
     * that exact point reconnectGeneration has already moved past the
     * observer's own [ownedGeneration], while _state is still Connected and
     * activeTransport is still the same instance (connect()'s own early
     * "already Connected" return, reached only after it eventually gets the
     * mutex, confirms neither was ever touched). If the fix were removed,
     * the pre-existing checks alone would see exactly that - _state
     * Connected, activeTransport unchanged - and incorrectly let the stale
     * observer tear the session down.
     */
    @Test
    fun `a stale observer is rejected by a reconnect-generation change even when state and transport identity look unchanged`() = runTest {
        val (controller, transport) = connectWithReconnectManager { n -> TransportStats.Counters(bytesReceived = 0L, bytesSent = n * 50L, lastHandshakeEpochMillis = System.currentTimeMillis()) }
        val reconnectManager = reconnectManagerForLastController!!

        val release = CompletableDeferred<Unit>()
        backgroundScope.launch { controller.holdConnectMutexForTest(release) }
        runCurrent()

        advanceTimeBy(31_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.Connected)
        // The stale observer is now parked on connectMutex - it queued for
        // the lock before either of the two bumps below ever existed.

        // Bump #1: starts a reconnect (generation -> 2); its reconnectLoop
        // job is scheduled but, with no runCurrent() yet, never dispatched.
        reconnectManager.triggerNetworkLost()
        // Bump #2: a second explicit connect() call's own synchronous
        // prefix (cancelReconnectForExplicitConnect) cancels that
        // not-yet-started reconnectJob BEFORE it is ever resumed for the
        // first time - so reconnectLoop(generation=2) never runs its body -
        // and bumps the generation again (to 3). connect() then itself
        // queues on the same still-held connectMutex, behind the observer.
        // CoroutineStart.UNDISPATCHED runs that synchronous prefix right
        // here, on this call, strictly before reconnectLoop(2)'s own
        // scope.launch (from bump #1) is ever dispatched by runCurrent().
        backgroundScope.launch(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { controller.connect() }
        runCurrent()

        // Neither bump needed the mutex or ran any state-changing code:
        // reconnectLoop(2) was cancelled before its first dispatch, and
        // connect() is still queued behind the held lock.
        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(0, transport.disconnectCallCount)

        // Release the mutex. Mutex's documented FIFO fairness hands it to
        // the observer (queued first) before connect() (queued second), so
        // the observer's ownership check is the first thing to run, with
        // _state/activeTransport still exactly as they were and only
        // reconnectGeneration (3, not the observer's own 1) having moved.
        release.complete(Unit)
        runCurrent()

        assertTrue(
            "the stale observer must be rejected by the generation check even " +
                "though _state/activeTransport were still provably unchanged when " +
                "its own check ran - saw ${controller.state.value}",
            controller.state.value !is TransportState.Error,
        )
        assertEquals(0, transport.disconnectCallCount)
    }
}
