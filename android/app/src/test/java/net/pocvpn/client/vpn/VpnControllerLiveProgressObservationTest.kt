@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

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
}
