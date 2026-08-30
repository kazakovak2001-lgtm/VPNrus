@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.network.NetworkProfile
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B13 - Section G: proves VpnController writes real, authoritative outcomes
 * into PathHistoryStore, and ONLY those - no hypothetical candidates, no
 * "Connecting", no duplicate writes, endpoint-scoped correctly.
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

private class RecordingPathHistoryStore : PathHistoryStore {
    data class Record(val fingerprint: String, val endpointId: EndpointId, val transport: TransportKind, val success: Boolean)

    val records = mutableListOf<Record>()

    override fun get(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind) = null

    override fun record(networkFingerprint: String, endpointId: EndpointId, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {
        records += Record(networkFingerprint, endpointId, transport, success)
    }
}

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

class VpnControllerPathHistoryTest {

    private fun newController(
        transport: FakeVpnTransport,
        pathHistoryStore: PathHistoryStore?,
        gateway: GatewayConfiguration = configuredGateway(),
        scope: kotlinx.coroutines.CoroutineScope,
    ) = VpnController(
        transport, FakeClientKeyRepository(),
        FakeGatewayConfigurationRepository(gateway),
        FakeReconnectManager(), DiagnosticsStore(), scope,
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        networkProfileProvider = { fakeUsableNetworkProfile },
    )

    @Test
    fun `a real fresh handshake records exactly one SUCCESS path-history entry for the real endpoint and transport`() = runTest {
        val transport = FakeVpnTransport()
        val store = RecordingPathHistoryStore()
        val controller = newController(transport, store, scope = backgroundScope)

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(1, store.records.size)
        val record = store.records.single()
        assertTrue(record.success)
        assertEquals(TransportKind.AMNEZIA_WG, record.transport)
        assertEquals(EndpointId(ProductionGateway.ID), record.endpointId)
    }

    @Test
    fun `a handshake timeout records exactly one FAILURE path-history entry`() = runTest {
        val transport = FakeVpnTransport()
        transport.handshakeAvailable = false
        val store = RecordingPathHistoryStore()
        val controller = newController(transport, store, scope = backgroundScope)

        controller.connect()
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.HandshakeFailed)
        assertEquals(1, store.records.size)
        assertTrue(!store.records.single().success)
    }

    @Test
    fun `no pathHistoryStore wired records nothing - purely additive, no crash`() = runTest {
        val transport = FakeVpnTransport()
        val controller = newController(transport, pathHistoryStore = null, scope = backgroundScope)

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
    }

    @Test
    fun `a merely Connecting state never produces a path-history write`() = runTest {
        val transport = FakeVpnTransport()
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        transport.connectGate = gate
        val store = RecordingPathHistoryStore()
        val controller = newController(transport, store, scope = backgroundScope)

        val job = backgroundScope.launch { controller.connect() }
        runCurrent()

        // transport.connect() is still suspended on connectGate - no
        // authoritative outcome exists yet, so no write must have happened.
        assertTrue(controller.state.value is TransportState.Connecting)
        assertEquals(0, store.records.size)

        gate.complete(Unit)
        job.cancel()
    }

    @Test
    fun `exhausted reconnect records exactly one FAILURE path-history entry for the whole cycle`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val store = RecordingPathHistoryStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            pathHistoryStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )

        controller.connect()
        runCurrent()
        assertEquals(1, store.records.size) // the initial successful connect

        transport.handshakeAvailable = false
        reconnectManager.triggerNetworkLost()
        reconnectManager.networkAvailable = true
        advanceTimeBy(300_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Error)
        assertEquals(2, store.records.size)
        assertTrue(!store.records.last().success)
    }

    @Test
    fun `a network-loss recovery that never exhausts produces no extra path-history write`() = runTest {
        val transport = FakeVpnTransport()
        val reconnectManager = FakeReconnectManager()
        val store = RecordingPathHistoryStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager, DiagnosticsStore(), backgroundScope,
            pathHistoryStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )

        controller.connect()
        runCurrent()
        reconnectManager.triggerNetworkLost()
        runCurrent()
        assertTrue(controller.state.value is TransportState.Reconnecting)

        reconnectManager.networkAvailable = true
        advanceTimeBy(5_000)
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        // Only the initial connect's SUCCESS - same "one record per real
        // attempt, not per recovery" model as ConnectionOutcome.
        assertEquals(1, store.records.size)
    }

    // B13 audit fix regression tests (2026-08-30 correctness audit item 3:
    // exact write counts through AWG -> Xray failover, and item 4: no
    // stale-endpoint reuse across a fresh connect() for a different endpoint).

    private val validXrayProfile = XrayProfile(
        server = "152.70.43.1",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "a1b2c3d4",
    )

    @Test
    fun `AWG failure followed by a successful Xray failover records exactly one path-history entry, not two`() = runTest {
        val awgTransport = FakeVpnTransport()
        awgTransport.handshakeAvailable = false
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val store = RecordingPathHistoryStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfile),
            pathHistoryStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )

        // Initial AWG attempt - handshake never lands, records one FAILURE.
        controller.connect()
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()
        assertTrue(controller.state.value is TransportState.HandshakeFailed)
        assertEquals(1, store.records.size)

        // Simulates MainViewModel.maybeFailoverToXray(): detach AWG, then
        // execute the SAME endpoint's XRAY_REALITY resolution.
        controller.disconnect()
        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, EndpointId(ProductionGateway.ID)))
        runCurrent()

        // Xray's own connect() succeeds (no exception) - per doConnectAttempt's
        // own "no ConnectionOutcome/PathHistory recording for a non-exception
        // XRAY_REALITY branch" model (this codebase has no proven Xray
        // handshake-evidence channel yet) - so still exactly ONE record total,
        // never a second one fabricated for the failover attempt.
        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(1, store.records.size)
        assertTrue(!store.records.single().success)
        assertEquals(TransportKind.AMNEZIA_WG, store.records.single().transport)
    }

    @Test
    fun `AWG failure followed by a failed Xray failover records exactly two distinct path-history entries`() = runTest {
        val awgTransport = FakeVpnTransport()
        awgTransport.handshakeAvailable = false
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        xrayTransport.failConnectWith = RuntimeException("simulated Xray backend start failure")
        val store = RecordingPathHistoryStore()
        val controller = VpnController(
            awgTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfile),
            pathHistoryStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )

        controller.connect()
        runCurrent()
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(1, store.records.size)

        controller.disconnect()
        controller.connect(TransportOrchestrator.Resolution.Resolved(xrayTransport, TransportKind.XRAY_REALITY, EndpointId(ProductionGateway.ID)))
        runCurrent()

        // TWO real, DISTINCT authoritative failures (AWG handshake timeout,
        // then a genuinely separate Xray backend-start exception) - not a
        // duplicate of the same logical failure.
        assertEquals(2, store.records.size)
        assertTrue(store.records.none { it.success })
        assertEquals(TransportKind.AMNEZIA_WG, store.records[0].transport)
        assertEquals(TransportKind.XRAY_REALITY, store.records[1].transport)
    }

    @Test
    fun `a fresh connect for a different endpoint never records against the previous, now-stale endpoint`() = runTest {
        val transport = FakeVpnTransport()
        val store = RecordingPathHistoryStore()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            pathHistoryStore = store,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
        )

        val endpointA = EndpointId("gateway-a")
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, endpointA))
        runCurrent()
        assertEquals(1, store.records.size)
        assertEquals(endpointA, store.records.single().endpointId)

        controller.disconnect()
        runCurrent()

        // A genuinely NEW attempt for a DIFFERENT endpoint - must record
        // against endpoint B, never silently reuse the stale endpointA value
        // pendingConnectEndpointId held from the previous, now-disconnected session.
        val endpointB = EndpointId("gateway-b")
        controller.connect(TransportOrchestrator.Resolution.Resolved(transport, TransportKind.AMNEZIA_WG, endpointB))
        runCurrent()

        assertEquals(2, store.records.size)
        assertEquals(endpointB, store.records.last().endpointId)
        // The FIRST record (endpoint A) must remain exactly as it was -
        // never rewritten/reattributed to endpoint B in place.
        assertEquals(endpointA, store.records.first().endpointId)
    }
}
