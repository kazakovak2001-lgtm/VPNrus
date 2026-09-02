@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import android.content.Intent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
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
import net.pocvpn.client.reachability.PathHistoryEntry
import net.pocvpn.client.reachability.PathHistoryStore
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.relay.NotConfiguredRelayEndToEndProbe
import net.pocvpn.client.relay.IngressClientProfile
import net.pocvpn.client.relay.RelayEndToEndProbe
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
import net.pocvpn.client.relay.RelayProbeResult
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.relay.fakeIngressClientProfile
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
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

private class AlwaysAutoModeStoreForE2ETeardown : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

private val richSuccessHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = true)
private val richFailureHistory = PathHistoryEntry(successCount = 0, failureCount = 10, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = false)

/** Seeds PathHistoryStore.get() deterministically by pathId (endpoint id for Direct, composite historyPathId for Relayed) - lets a test force a deterministic PathScorer ranking without faking reachability/health evidence. record() is tracked for D/E assertions. */
private class RecordingSeededPathHistoryStore(private val entries: Map<String, PathHistoryEntry>) : PathHistoryStore {
    data class Record(val pathId: String, val transport: TransportKind, val success: Boolean)
    val records = mutableListOf<Record>()
    override fun get(networkFingerprint: String, pathId: String, transport: TransportKind): PathHistoryEntry? = entries[pathId]
    override fun record(networkFingerprint: String, pathId: String, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {
        records += Record(pathId, transport, success)
    }
}

/** A real VpnTransport double: connect() reaches a genuine Connected state and tracks how many times disconnect() was actually called - the direct proof this bug's fix requires (task A's own "old ingress transport disconnect() is called"). */
private class TrackingHandshakeTransport(override val kind: TransportKind = TransportKind.AMNEZIA_WG) : VpnTransport {
    override val name: String = "tracking-handshake"
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    var disconnectCallCount = 0
        private set

    override fun preparePermissionIntent(): Intent? = null
    override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
        connectCallCount++
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() {
        disconnectCallCount++
        stateFlow.value = TransportState.Disconnected
    }
    override fun observeState(): Flow<TransportState> = stateFlow
}

private class TeardownStubRelayIngressResolver(private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        return resolutionFor(plan)
    }
}

private class TeardownStubRelayEndToEndProbe(private val resultFor: (RelayedExecutionPlan) -> RelayProbeResult) : RelayEndToEndProbe {
    val probedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun probe(plan: RelayedExecutionPlan, profile: IngressClientProfile): RelayProbeResult {
        probedPlans += plan
        return resultFor(plan)
    }
}

/**
 * B25 review fix (PR #39) - proves `VpnController.abandonAttemptForFailover()`
 * actually unblocks the combined coordinator after a relayed attempt's
 * ingress handshake succeeds but its real end-to-end probe fails: without
 * it, `controller.connect()` for the NEXT combined candidate is silently
 * swallowed by `connect()`'s own `state is Connecting || Connected`
 * early-return guard, since nothing ever tore the failed ingress session
 * down.
 */
class MainViewModelRelayE2ETeardownTest {

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

    private val germany = ProductionGatewayCatalog.GERMANY
    private val ingressA = EndpointId("ru-ingress-a")
    private val ingressB = EndpointId("ru-ingress-b")

    private fun sign(manifest: EndpointManifest): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, manifestSigningKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return SignedManifest(manifest, signer.generateSignature())
    }

    private fun manifestRepository(endpoints: List<EndpointDescriptor>): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = endpoints,
        )
        return EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = manifestTrustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = sign(manifest),
            nowEpochMillis = { 2_000L },
        )
    }

    /** Germany (Direct, GATEWAY+EXIT) + ingressA (INGRESS relaying to Germany), ingressA ranked FIRST. */
    private fun manifestWithGermanyAndIngressA(): EndpointManifestRepository = manifestRepository(
        listOf(
            EndpointDescriptor(
                id = germany.endpointId,
                roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                region = "Germany / Frankfurt", provider = "Oracle Cloud",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
            ),
            EndpointDescriptor(
                id = ingressA, roles = setOf(EndpointRole.INGRESS),
                region = "ru", provider = "operator-a",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.50", 51820)),
                relayTo = germany.endpointId,
            ),
        ),
    )

    /**
     * Germany (EXIT - required for a valid relayTo target, per
     * PathCandidateBuilder.buildRelayed's own "exit needs GATEWAY or EXIT"
     * requirement) + ingressA + ingressB, both relaying to Germany. Note:
     * an EXIT-role endpoint is ALSO always eligible as a Direct candidate
     * (PathCandidateBuilder.buildDirect accepts GATEWAY OR EXIT) - there is
     * no way to have a valid relay target that isn't also a Direct
     * candidate - so this manifest still produces THREE combined attempts;
     * the test seeds history so Germany ranks LAST, below both ingresses.
     */
    private fun manifestWithTwoIngresses(): EndpointManifestRepository = manifestRepository(
        listOf(
            EndpointDescriptor(
                id = germany.endpointId, roles = setOf(EndpointRole.EXIT),
                region = "Germany / Frankfurt", provider = "Oracle Cloud",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
            ),
            EndpointDescriptor(
                id = ingressA, roles = setOf(EndpointRole.INGRESS),
                region = "ru", provider = "operator-a",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.50", 51820)),
                relayTo = germany.endpointId,
            ),
            EndpointDescriptor(
                id = ingressB, roles = setOf(EndpointRole.INGRESS),
                region = "ru", provider = "operator-b",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.51", 51820)),
                relayTo = germany.endpointId,
            ),
        ),
    )

    /** Germany + Stockholm, both Direct - no ingress at all (test G's Direct-only control). */
    private fun manifestWithGermanyAndStockholmDirectOnly(): EndpointManifestRepository {
        val stockholm = ProductionGatewayCatalog.STOCKHOLM
        return manifestRepository(
            listOf(
                EndpointDescriptor(
                    id = germany.endpointId, roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Germany / Frankfurt", provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
                ),
                EndpointDescriptor(
                    id = stockholm.endpointId, roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Sweden / Stockholm", provider = "AWS",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, stockholm.awg.endpointHost, stockholm.awg.endpointPort)),
                ),
            ),
        )
    }

    private fun newViewModel(
        transport: VpnTransport,
        relayIngressResolver: RelayIngressResolver,
        relayEndToEndProbe: RelayEndToEndProbe = NotConfiguredRelayEndToEndProbe,
        manifestRepository: EndpointManifestRepository,
        pathHistoryStore: PathHistoryStore? = null,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(
            mapOf(net.pocvpn.client.vpn.config.ProductionGatewayId.GERMANY to "10.77.0.5", net.pocvpn.client.vpn.config.ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        ),
        gatewayAutoModeStore = AlwaysAutoModeStoreForE2ETeardown(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepository,
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressResolver = relayIngressResolver,
        relayEndToEndProbe = relayEndToEndProbe,
    )

    // B27 - every ingress fixture in this file declares no withIngressKind()
    // at all, so its historyPathId defaults to DIRECT_IP - see
    // PathCandidate.Relayed.historyPathId's own docs for the format.
    private fun compositeHistoryPathId(ingressId: EndpointId, exitId: EndpointId) =
        "${ingressId.value}:${net.pocvpn.client.reachability.IngressKind.DIRECT_IP}:${TransportKind.AMNEZIA_WG}->${exitId.value}:${TransportKind.AMNEZIA_WG}"

    // --- A: ingress Connected, E2E fails -> transport.disconnect() called -> controller no longer Connected -> Direct B actually connects ---

    @Test
    fun `A - a failed E2E probe tears down the ingress transport and the next Direct candidate actually connects`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory, germany.endpointId.value to richFailureHistory),
        )
        val ingressTransport = TrackingHandshakeTransport()
        val directTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(directTransport, resolver, probe, manifestWithGermanyAndIngressA(), history)

        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.first() is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, ingressTransport.connectCallCount)
        assertEquals(1, ingressTransport.disconnectCallCount)
        // The bug this fixes: without abandonAttemptForFailover(), connect()
        // for Germany would be silently swallowed and this would stay 0.
        assertEquals(1, directTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    // --- B: ingress Connected, E2E fails -> the next RELAYED candidate actually connects ---

    @Test
    fun `B - a failed E2E probe on Relayed A lets Relayed B actually connect next`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(
                compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory,
                germany.endpointId.value to richFailureHistory,
            ),
        )
        val transportA = TrackingHandshakeTransport()
        val transportB = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan ->
            val transport = if (plan.ingressEndpointId == ingressA) transportA else transportB
            RelayIngressResolution.Resolved(transport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan))
        }
        val probe = TeardownStubRelayEndToEndProbe { plan ->
            if (plan.ingressEndpointId == ingressA) RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") else RelayProbeResult.Success
        }
        val viewModel = newViewModel(TrackingHandshakeTransport(), resolver, probe, manifestWithTwoIngresses(), history)

        // Germany (Direct) is also a structurally-valid candidate here (see
        // manifestWithTwoIngresses's own docs) but ranks LAST - both
        // Relayed candidates outrank it.
        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts[0] is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)
        assertTrue(attempts[1] is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transportA.connectCallCount)
        assertEquals(1, transportA.disconnectCallCount)
        // The bug this fixes: without teardown, ingressB's own connect()
        // would be silently swallowed and this would stay 0.
        assertEquals(1, transportB.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.RelayProtected, viewModel.sessionHealth.value)
    }

    // --- C: no stale RelayHandshake/RelayProtected session health survives teardown ---

    @Test
    fun `C - no stale RelayHandshake or RelayProtected session health survives the teardown`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory, germany.endpointId.value to richFailureHistory),
        )
        val ingressTransport = TrackingHandshakeTransport()
        val directTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(directTransport, resolver, probe, manifestWithGermanyAndIngressA(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // The final settled health is the NEW Direct session's own
        // DirectProtected - never a leftover RelayHandshake/RelayProtected
        // from the abandoned relay attempt.
        assertEquals(VpnSessionHealth.DirectProtected, viewModel.sessionHealth.value)
    }

    // --- D: the failed relay historyPathId is recorded exactly once ---

    @Test
    fun `D - the failed relay historyPathId is recorded exactly once`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory, germany.endpointId.value to richFailureHistory),
        )
        val ingressTransport = TrackingHandshakeTransport()
        val directTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(directTransport, resolver, probe, manifestWithGermanyAndIngressA(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        val compositeId = compositeHistoryPathId(ingressA, germany.endpointId)
        val relayRecords = history.records.filter { it.pathId == compositeId }
        assertEquals(1, relayRecords.size)
        assertFalse(relayRecords.single().success)
    }

    // --- E: the teardown itself does not create a single-hop relay PathHistoryStore record ---

    @Test
    fun `E - the teardown does not create a single-hop PathHistoryStore record keyed by the bare ingress endpoint id`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory, germany.endpointId.value to richFailureHistory),
        )
        val ingressTransport = TrackingHandshakeTransport()
        val directTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(directTransport, resolver, probe, manifestWithGermanyAndIngressA(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(
            "abandonAttemptForFailover()'s own teardown (transport.disconnect()) must never write a single-hop record under the bare ingress endpoint id",
            history.records.any { it.pathId == ingressA.value },
        )
    }

    // --- F: the combined attempt key/budget behavior is unchanged - each candidate consumed exactly once ---

    @Test
    fun `F - the combined attempt budget consumes each candidate exactly once across the teardown`() = runTest {
        val history = RecordingSeededPathHistoryStore(
            mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory, germany.endpointId.value to richFailureHistory),
        )
        val ingressTransport = TrackingHandshakeTransport()
        val directTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(directTransport, resolver, probe, manifestWithGermanyAndIngressA(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, resolver.resolvedPlans.size)
        assertEquals(1, probe.probedPlans.size)
        assertEquals(1, ingressTransport.connectCallCount)
        assertEquals(1, directTransport.connectCallCount)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted != true)
    }

    // --- G: Direct-only failure/failover behavior remains regression-safe ---

    @Test
    fun `G - Direct-only failover (no relay involved at all) remains regression-safe`() = runTest {
        val stockholm = ProductionGatewayCatalog.STOCKHOLM
        val history = RecordingSeededPathHistoryStore(
            mapOf(germany.endpointId.value to richFailureHistory, stockholm.endpointId.value to richSuccessHistory),
        )
        val germanyTransport = TrackingHandshakeTransport()
        // Both AWG candidates dial through the SAME constructor-owned
        // transport instance (see buildTransportRegistry's own docs) - a
        // transport that fails once then succeeds mirrors a real
        // Germany-fails/Stockholm-succeeds sequence.
        val failThenSucceed = object : VpnTransport by germanyTransport {
            var calls = 0
            override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
                calls++
                if (calls == 1) throw RuntimeException("simulated Germany failure")
                germanyTransport.connect(config)
            }
        }
        val resolver = TeardownStubRelayIngressResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED) }
        val viewModel = newViewModel(failThenSucceed, resolver, manifestRepository = manifestWithGermanyAndStockholmDirectOnly(), pathHistoryStore = history)

        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.all { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt })

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, failThenSucceed.calls)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    // --- H: a successful relay E2E probe does NOT tear down the session ---

    @Test
    fun `H - a successful end-to-end probe never disconnects the ingress transport`() = runTest {
        val history = RecordingSeededPathHistoryStore(mapOf(compositeHistoryPathId(ingressA, germany.endpointId) to richSuccessHistory))
        val ingressTransport = TrackingHandshakeTransport()
        val resolver = TeardownStubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(ingressTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = TeardownStubRelayEndToEndProbe { RelayProbeResult.Success }
        val viewModel = newViewModel(TrackingHandshakeTransport(), resolver, probe, manifestWithGermanyAndIngressA(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, ingressTransport.connectCallCount)
        assertEquals(0, ingressTransport.disconnectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(VpnSessionHealth.RelayProtected, viewModel.sessionHealth.value)
    }
}
