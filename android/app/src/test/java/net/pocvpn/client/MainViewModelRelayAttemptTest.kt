@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.reachability.CoarseNetworkSignals
import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointManifestRepository
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.FileLastKnownGoodManifestStore
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.NetworkFingerprintKeyProvider
import net.pocvpn.client.reachability.NetworkFingerprinter
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.relay.NotProvisionedRelayIngressDialer
import net.pocvpn.client.relay.RelayAttemptOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressDialer
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

private fun configuredGateway() = GatewayConfiguration.Configured(
    endpointHost = "203.0.113.10",
    endpointPort = 51820,
    serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
    clientTunnelIp = "10.77.0.2",
    gatewayTunnelIp = "10.77.0.1",
    allowedIps = listOf("0.0.0.0/0", "::/0"),
    profile = AwgProfile.none(),
)

private val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
    type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
    roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
    vpnActive = false, generation = 1,
)

/** In-memory GatewayAutoModeStore double, always-on for this file's tests. */
private class AlwaysAutoModeStore : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

/** In-memory PathHistoryStore double that records every write for inspection. */
private class RecordingPathHistoryStore : PathHistoryStore {
    data class Record(val fingerprint: String, val pathId: String, val transport: TransportKind, val success: Boolean)

    val records = mutableListOf<Record>()

    override fun get(networkFingerprint: String, pathId: String, transport: TransportKind): PathHistoryEntry? = null

    override fun record(networkFingerprint: String, pathId: String, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {
        records += Record(networkFingerprint, pathId, transport, success)
    }
}

/** A dialer stub that always returns the given outcome and records every plan it was called with. */
private class StubRelayIngressDialer(private val outcomeFor: (RelayedExecutionPlan) -> RelayAttemptOutcome) : RelayIngressDialer {
    val dialedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun dial(plan: RelayedExecutionPlan): RelayAttemptOutcome {
        dialedPlans += plan
        return outcomeFor(plan)
    }
}

/**
 * B24 - proves the real client execution integration: a combined-attempt
 * winner is handed to [net.pocvpn.client.relay.RelayIngressDialer], the
 * outcome is recorded under the FULL relayed historyPathId (never poisoning
 * either hop's own Direct history), a relay failure fails closed with the
 * correct typed category and never claims Protected, and bounded retry never
 * mutates a candidate's own pinned identity.
 */
class MainViewModelRelayAttemptTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("test-manifest-key") to manifestSigningKey.generatePublicKey().encoded),
    )

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private val ingressId = EndpointId("ru-ingress-1")

    /** A trusted, signed manifest naming ONE INGRESS (relayTo Germany) and Germany itself as EXIT - no Stockholm, no Direct alternative, so a relay attempt failure has nothing else to fall back to except NoCandidateAvailable. */
    private fun manifestRepositoryWithIngressOnly(): EndpointManifestRepository {
        val germany = ProductionGatewayCatalog.GERMANY
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = germany.endpointId,
                    roles = setOf(EndpointRole.EXIT),
                    region = "Germany / Frankfurt",
                    provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
                ),
                EndpointDescriptor(
                    id = ingressId,
                    roles = setOf(EndpointRole.INGRESS),
                    region = "ru",
                    provider = "operator-a",
                    // B24 test note - AMNEZIA_WG here (not the real
                    // architecture's preferred XRAY_REALITY/TLS_TCP - see
                    // AutoGatewaySelectorTest's own dedicated TLS_TCP-based
                    // coverage for THAT) purely so this integration test's
                    // registry (FakeVpnTransport's AWG entry is always
                    // AVAILABLE) doesn't also need a wired
                    // XrayTlsProfileRepository double just to prove the
                    // MainViewModel wiring itself - orthogonal concerns.
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.50", 51820)),
                    relayTo = germany.endpointId,
                ),
            ),
        )
        val signer = Ed25519Signer()
        signer.init(true, manifestSigningKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        val signed = SignedManifest(manifest, signer.generateSignature())
        return EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = manifestTrustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = signed,
            nowEpochMillis = { 2_000L },
        )
    }

    private fun newViewModel(
        transport: VpnTransport = FakeVpnTransport(),
        relayIngressDialer: RelayIngressDialer = NotProvisionedRelayIngressDialer,
        pathHistoryStore: PathHistoryStore? = null,
        fingerprintKeyProvider: NetworkFingerprintKeyProvider? = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        gatewayAutoModeStore = AlwaysAutoModeStore(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepositoryWithIngressOnly(),
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = fingerprintKeyProvider,
        relayIngressDialer = relayIngressDialer,
    )

    // --- Task requirement A/B (integration level) ---

    @Test
    fun `combinedAutoAttempts contains the relay candidate built from the ingress-only manifest`() {
        val viewModel = newViewModel()
        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt })
        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().first().candidate
        assertEquals(ingressId, relayed.ingressEndpointId)
        assertEquals(ProductionGatewayCatalog.GERMANY.endpointId, relayed.exitEndpointId)
    }

    // --- Task requirement G: relay history recorded ONLY under the full historyPathId ---

    @Test
    fun `a failed relay attempt records history under the full relayed historyPathId, never under either hop's endpoint id alone`() = runTest {
        val store = RecordingPathHistoryStore()
        val dialer = StubRelayIngressDialer { plan ->
            RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_REACHABLE, category = RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val viewModel = newViewModel(relayIngressDialer = dialer, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(store.records.isNotEmpty())
        assertTrue(store.records.all { it.pathId.contains("->") })
        assertFalse(store.records.any { it.pathId == ingressId.value })
        assertFalse(store.records.any { it.pathId == ProductionGatewayCatalog.GERMANY.endpointId.value })
        assertFalse(store.records.first().success)
    }

    // --- Task requirement H: a lower readiness stage never becomes Protected/Connected ---

    @Test
    fun `an ingress handshake success without a confirmed data plane never transitions transportState to Connected`() = runTest {
        val dialer = StubRelayIngressDialer { plan ->
            RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_HANDSHAKE_OK, category = RelayFailureCategory.UPSTREAM_EXIT_HANDSHAKE_FAILED)
        }
        val viewModel = newViewModel(relayIngressDialer = dialer)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is TransportState.Connected)
    }

    // --- Task requirement I: upstream failure surfaces the correct typed failure ---

    @Test
    fun `an upstream exit failure surfaces UPSTREAM_EXIT_UNREACHABLE, never a generic handshake timeout`() = runTest {
        val dialer = StubRelayIngressDialer { plan ->
            RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_HANDSHAKE_OK, category = RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE)
        }
        val viewModel = newViewModel(relayIngressDialer = dialer)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        val reason = viewModel.autoGatewayDiagnostics.value?.lastFailureReason
        assertTrue("expected UPSTREAM_EXIT_UNREACHABLE in '$reason'", reason?.contains("UPSTREAM_EXIT_UNREACHABLE") == true)
    }

    // --- Task requirement J: relay auth failure fails closed ---

    @Test
    fun `a RELAY_AUTH_FAILED outcome fails closed - never Connected, and the auto attempt is exhausted with no other candidate`() = runTest {
        val dialer = StubRelayIngressDialer { plan ->
            RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_HANDSHAKE_OK, category = RelayFailureCategory.RELAY_AUTH_FAILED)
        }
        val viewModel = newViewModel(relayIngressDialer = dialer)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is TransportState.Connected)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
        val reason = viewModel.autoGatewayDiagnostics.value?.lastFailureReason
        assertTrue(reason?.contains("RELAY_AUTH_FAILED") == true)
    }

    // --- Task requirement K: bounded retry, never mutates the candidate's own exit/bindings ---

    @Test
    fun `a persistently failing relay is dialed a BOUNDED number of times, always with the SAME pinned ingress and exit bindings`() = runTest {
        val dialer = StubRelayIngressDialer { plan ->
            RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_REACHABLE, category = RelayFailureCategory.INGRESS_UNREACHABLE)
        }
        val viewModel = newViewModel(relayIngressDialer = dialer)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // With only ONE relay candidate available (no Direct alternative in
        // this manifest), the shared combined budget must dial it AT MOST
        // once - a persistently failing single candidate is never retried
        // in a loop (task's own "no unbounded retries").
        assertEquals(1, dialer.dialedPlans.size)
        val plan = dialer.dialedPlans.single()
        assertEquals(ingressId, plan.ingressEndpointId)
        assertEquals(ProductionGatewayCatalog.GERMANY.endpointId, plan.exitEndpointId)
    }

    @Test
    fun `NotProvisionedRelayIngressDialer (the production default) never claims relay success - connect() fails closed`() = runTest {
        val viewModel = newViewModel()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is TransportState.Connected)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.lastFailureReason?.contains("EXECUTION_NOT_IMPLEMENTED") == true)
    }
}
