@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn

import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.relay.VpnAttemptContext
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B25 - proves task A (typed attempt identity pinned through VpnController),
 * task B (Protected gating via [VpnSessionHealth], never derived directly
 * from [TransportState] for a relayed attempt), and task D (VpnController's
 * generic recordConnectionOutcome/recordPathHistory never fires a second,
 * single-hop write for a relayed attempt - see that catch block's own docs).
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

private val fakeUsableNetworkProfile = net.pocvpn.client.network.NetworkProfile(
    type = net.pocvpn.client.network.NetworkType.WIFI,
    validatedInternet = true, metered = false, roaming = false, captivePortal = false,
    ipv4Available = true, ipv6Available = false, vpnActive = false, generation = 1,
    dnsServerAddresses = listOf("1.1.1.1"),
)

private class RelayRecordingPathHistoryStore : PathHistoryStore {
    val records = mutableListOf<String>()
    override fun get(networkFingerprint: String, pathId: String, transport: TransportKind) = null
    override fun record(networkFingerprint: String, pathId: String, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {
        records += pathId
    }
}

private class RecordingConnectionOutcomeStore : ConnectionOutcomeStore {
    var recordCount = 0
        private set
    override fun record(outcome: net.pocvpn.client.smartconnect.ConnectionOutcome) { recordCount++ }
    override fun recent(): List<net.pocvpn.client.smartconnect.ConnectionOutcome> = emptyList()
}

private fun relayedPlan() = RelayedExecutionPlan(
    ingressEndpointId = EndpointId("ru-ingress-1"),
    ingressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 443),
    ingressTransport = TransportKind.XRAY_REALITY,
    ingressKind = IngressKind.DIRECT_IP,
    exitEndpointId = EndpointId("germany"),
    exitBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.60", 51820),
    exitTransport = TransportKind.AMNEZIA_WG,
    historyPathId = "ru-ingress-1:XRAY_REALITY->germany:AMNEZIA_WG",
)

class VpnControllerRelayTest {

    // --- task B: Direct behavior is completely unaffected ---

    @Test
    fun `a Direct attempt reaching Connected reports DirectProtected sessionHealth`() = runTest {
        val transport = FakeVpnTransport()
        val controller = VpnController(
            transport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
        )

        controller.connect()
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.DirectProtected, controller.sessionHealth.value)
    }

    // --- task B: a relayed attempt reaching Connected is NEVER Protected until the real stage is reported ---

    @Test
    fun `a relayed attempt reaching Connected reports RelayHandshake, never RelayProtected, until a real stage is reported`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
            server = "203.0.113.50", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
            flow = "", serverName = "example.com", fingerprint = "chrome",
            realityPublicKey = "A".repeat(43), shortId = "ab",
        ))
        val plan = relayedPlan()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), DiagnosticsStore(), backgroundScope,
            relayXrayProfileRepositoryResolver = net.pocvpn.client.identity.XrayProfileRepositoryResolver { id -> if (id == plan.ingressEndpointId) xrayRepository else null },
        )

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                transport = xrayTransport,
                kind = TransportKind.XRAY_REALITY,
                endpointId = plan.ingressEndpointId,
                attemptContext = VpnAttemptContext.Relayed(plan),
            ),
        )
        runCurrent()

        assertTrue(controller.state.value is TransportState.Connected)
        assertTrue(
            "a relayed ingress handshake alone must never report RelayProtected",
            controller.sessionHealth.value !is VpnSessionHealth.RelayProtected,
        )

        controller.reportRelayStage(RelayReadinessStage.END_TO_END_DATA_PLANE_OK)
        assertEquals(VpnSessionHealth.RelayProtected, controller.sessionHealth.value)
    }

    // --- task D: no single-hop PathHistoryStore/ConnectionOutcomeStore write for a relayed attempt ---

    @Test
    fun `a relayed attempt whose transport connect() throws records no single-hop path-history or connection-outcome entry`() = runTest {
        val throwingTransport = object : VpnTransport {
            override val name: String = "throwing-ingress"
            override val kind: TransportKind = TransportKind.XRAY_REALITY
            override val capabilities: net.pocvpn.client.transport.TransportCapabilities = net.pocvpn.client.transport.TransportCapabilities.xrayRealityAdapterShell()
            override fun preparePermissionIntent(): android.content.Intent? = null
            override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
                throw RuntimeException("simulated ingress backend failure")
            }
            override suspend fun disconnect() {}
            override fun observeState(): kotlinx.coroutines.flow.Flow<TransportState> = kotlinx.coroutines.flow.MutableStateFlow(TransportState.Disconnected)
        }
        val plan = relayedPlan()
        val pathHistoryStore = RelayRecordingPathHistoryStore()
        val connectionOutcomeStore = RecordingConnectionOutcomeStore()
        val xrayRepository = FakeXrayProfileRepository(net.pocvpn.client.identity.XrayProfile(
            server = "203.0.113.50", serverPort = 443, uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
            flow = "", serverName = "example.com", fingerprint = "chrome",
            realityPublicKey = "A".repeat(43), shortId = "ab",
        ))
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            FakeVpnTransport(), FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            pathHistoryStore = pathHistoryStore,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
            connectionOutcomeStore = connectionOutcomeStore,
            relayXrayProfileRepositoryResolver = net.pocvpn.client.identity.XrayProfileRepositoryResolver { id -> if (id == plan.ingressEndpointId) xrayRepository else null },
        )

        controller.connect(
            TransportOrchestrator.Resolution.Resolved(
                transport = throwingTransport,
                kind = TransportKind.XRAY_REALITY,
                endpointId = plan.ingressEndpointId,
                attemptContext = VpnAttemptContext.Relayed(plan),
            ),
        )
        runCurrent()

        // Note: not asserting on controller.state.value directly here - see
        // VpnControllerTest's own "currentTransportKind stays null throughout
        // a backend runtime failure" test for why a transport double's own
        // observeState() replay can race the catch block's Error assignment.
        // diagnostics.lastError is the authoritative, race-free signal that
        // the catch branch genuinely ran.
        assertEquals(net.pocvpn.client.diagnostics.VpnError.BackendStartFailure("RuntimeException"), diagnostics.snapshot.value.lastError)
        assertTrue(
            "relay evidence must be recorded ONLY by MainViewModel.recordRelayOutcome under the full historyPathId, never by this generic per-endpoint write",
            pathHistoryStore.records.isEmpty(),
        )
        assertEquals(0, connectionOutcomeStore.recordCount)
    }

    // --- task D control: the SAME failure for a Direct attempt still records exactly as before ---

    @Test
    fun `the SAME connect() throw for a Direct attempt still records path-history and connection-outcome (control, unaffected)`() = runTest {
        val throwingTransport = object : VpnTransport {
            override val name: String = "throwing-awg"
            override val kind: TransportKind = TransportKind.AMNEZIA_WG
            override val capabilities: net.pocvpn.client.transport.TransportCapabilities = net.pocvpn.client.transport.TransportCapabilities.amneziaWg()
            override fun preparePermissionIntent(): android.content.Intent? = null
            override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
                throw RuntimeException("simulated backend failure")
            }
            override suspend fun disconnect() {}
            override fun observeState(): kotlinx.coroutines.flow.Flow<TransportState> = kotlinx.coroutines.flow.MutableStateFlow(TransportState.Disconnected)
        }
        val pathHistoryStore = RelayRecordingPathHistoryStore()
        val connectionOutcomeStore = RecordingConnectionOutcomeStore()
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            throwingTransport, FakeClientKeyRepository(),
            FakeGatewayConfigurationRepository(configuredGateway()),
            FakeReconnectManager(), diagnostics, backgroundScope,
            pathHistoryStore = pathHistoryStore,
            fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
            networkProfileProvider = { fakeUsableNetworkProfile },
            connectionOutcomeStore = connectionOutcomeStore,
        )

        controller.connect()
        runCurrent()

        assertEquals(net.pocvpn.client.diagnostics.VpnError.BackendStartFailure("RuntimeException"), diagnostics.snapshot.value.lastError)
        assertEquals(1, pathHistoryStore.records.size)
        assertEquals(1, connectionOutcomeStore.recordCount)
    }
}
