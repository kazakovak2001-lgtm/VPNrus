@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import android.content.Intent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.runTest
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
import net.pocvpn.client.relay.RelayAttemptOutcome
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressDialer
import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertEquals
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

private class AlwaysAutoModeStoreForCombinedFailover : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

/**
 * B24 review fix (PR #38) test fixture - an AWG transport double that
 * records, in a SHARED order log (interleaved with the relay dialer's own
 * log entries - see [OrderLoggingDialer]), which real gateway host it was
 * asked to dial, always fails, and never succeeds - so the FULL bounded
 * combined sequence runs to exhaustion and its complete attempt order can
 * be asserted.
 */
private class OrderLoggingAlwaysFailTransport(
    private val orderLog: MutableList<String>,
    private val hostLabels: Map<String, String>,
) : VpnTransport {
    override val name: String = "order-logging-always-fail"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    val configs = mutableListOf<TransportConfig.Awg>()

    override fun preparePermissionIntent(): Intent? = null

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        val awg = config as TransportConfig.Awg
        configs += awg
        val label = hostLabels[awg.config.peer.endpointHost] ?: "direct:${awg.config.peer.endpointHost}"
        orderLog += label
        throw RuntimeException("simulated backend start failure")
    }

    override suspend fun disconnect() {
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

/** Same as above but succeeds on the Nth call (1-indexed) instead of always failing. */
private class OrderLoggingFailNThenSucceedTransport(
    private val orderLog: MutableList<String>,
    private val hostLabels: Map<String, String>,
    private val succeedOnCall: Int,
) : VpnTransport {
    override val name: String = "order-logging-fail-n-then-succeed"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    val configs = mutableListOf<TransportConfig.Awg>()

    override fun preparePermissionIntent(): Intent? = null

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        val awg = config as TransportConfig.Awg
        configs += awg
        val label = hostLabels[awg.config.peer.endpointHost] ?: "direct:${awg.config.peer.endpointHost}"
        orderLog += label
        if (connectCallCount < succeedOnCall) {
            throw RuntimeException("simulated backend start failure")
        }
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

private class OrderLoggingDialer(
    private val orderLog: MutableList<String>,
    private val outcomeFor: (RelayedExecutionPlan) -> RelayAttemptOutcome,
) : RelayIngressDialer {
    val dialedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun dial(plan: RelayedExecutionPlan): RelayAttemptOutcome {
        dialedPlans += plan
        orderLog += "relay:${plan.ingressEndpointId.value}"
        return outcomeFor(plan)
    }
}

/** A PathHistoryStore double whose get() always returns a pre-seeded entry keyed only by pathId - lets a test force a deterministic PathScorer history-tier ordering without needing to fake reachability/health evidence. */
private class SeededPathHistoryStore(private val entries: Map<String, PathHistoryEntry>) : PathHistoryStore {
    override fun get(networkFingerprint: String, pathId: String, transport: TransportKind): PathHistoryEntry? = entries[pathId]
    override fun record(networkFingerprint: String, pathId: String, transport: TransportKind, success: Boolean, nowEpochMillis: Long) {}
}

private val richSuccessHistory = PathHistoryEntry(successCount = 10, failureCount = 0, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = true)
private val richFailureHistory = PathHistoryEntry(successCount = 0, failureCount = 10, lastOutcomeEpochMillis = 1L, lastOutcomeSuccess = false)

/**
 * B24 review fix (PR #38) - proves the SINGLE combined bounded attempt
 * progression: after ANY terminal failure (Direct or Relayed), progression
 * returns to the SAME combined ranked list and picks the next
 * globally-ranked unattempted candidate, regardless of shape - never a
 * Direct-only remainder list "owned" by the old Direct failover loop.
 */
class MainViewModelCombinedFailoverTest {

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
    private val germany = ProductionGatewayCatalog.GERMANY
    private val stockholm = ProductionGatewayCatalog.STOCKHOLM

    private val hostLabels = mapOf(
        germany.awg.endpointHost to "direct:GERMANY",
        stockholm.awg.endpointHost to "direct:STOCKHOLM",
    )

    /**
     * A manifest naming Direct GERMANY, Direct STOCKHOLM, and an INGRESS
     * relaying to GERMANY (AMNEZIA_WG both hops - see
     * MainViewModelRelayAttemptTest's own note on why AMNEZIA_WG, not
     * XRAY_REALITY/TLS_TCP, keeps this an orchestration-only test).
     */
    private fun manifestRepositoryWithAllThree(): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = germany.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Germany / Frankfurt",
                    provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
                ),
                EndpointDescriptor(
                    id = stockholm.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Sweden / Stockholm",
                    provider = "AWS",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, stockholm.awg.endpointHost, stockholm.awg.endpointPort)),
                ),
                EndpointDescriptor(
                    id = ingressId,
                    roles = setOf(EndpointRole.INGRESS),
                    region = "ru",
                    provider = "operator-a",
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

    /**
     * A manifest naming ONLY Direct GERMANY and an INGRESS relaying to it -
     * for the two-candidate A/B scenarios.
     */
    private fun manifestRepositoryWithGermanyAndIngress(): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = germany.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Germany / Frankfurt",
                    provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
                ),
                EndpointDescriptor(
                    id = ingressId,
                    roles = setOf(EndpointRole.INGRESS),
                    region = "ru",
                    provider = "operator-a",
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
        transport: VpnTransport,
        relayIngressDialer: RelayIngressDialer,
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
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        ),
        gatewayAutoModeStore = AlwaysAutoModeStoreForCombinedFailover(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepository,
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressDialer = relayIngressDialer,
    )

    private fun alwaysFailingRelayOutcome(plan: RelayedExecutionPlan) =
        RelayAttemptOutcome.Failure(plan, highestStageReached = RelayReadinessStage.INGRESS_REACHABLE, category = RelayFailureCategory.INGRESS_UNREACHABLE)

    // --- A: Direct A fails -> Relayed B is attempted next (Relayed ranks ABOVE Direct STOCKHOLM here too - see D) ---

    @Test
    fun `A - a failing higher-ranked Direct candidate is followed by the next-ranked Relayed candidate`() = runTest {
        val orderLog = mutableListOf<String>()
        // GERMANY (Direct, rank 1: rich success history) then the relay
        // (rank 2: no history) - only two candidates exist in this manifest.
        val history = SeededPathHistoryStore(mapOf(germany.endpointId.value to richSuccessHistory))
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithGermanyAndIngress(), history)

        // Sanity: combined ranking really does put Direct GERMANY first.
        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.first() is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY", "relay:${ingressId.value}"), orderLog)
    }

    // --- B: Relayed A fails -> Direct B is attempted next ---

    @Test
    fun `B - a failing higher-ranked Relayed candidate is followed by the next-ranked Direct candidate`() = runTest {
        val orderLog = mutableListOf<String>()
        // The relay ranks ABOVE GERMANY here: GERMANY gets a rich FAILURE
        // history (historyRank -1), the relay gets none (historyRank 0).
        val history = SeededPathHistoryStore(mapOf(germany.endpointId.value to richFailureHistory))
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithGermanyAndIngress(), history)

        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.first() is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("relay:${ingressId.value}", "direct:GERMANY"), orderLog)
    }

    // --- C: Direct A fails, Relayed B fails -> Direct C is attempted next ---
    // --- D (same fixture): the failing Direct A cannot consume the whole Direct-only list before Relayed B ---

    @Test
    fun `C and D - Direct A fails, Relayed B fails, Direct C is attempted next - Relayed B is never skipped over`() = runTest {
        val orderLog = mutableListOf<String>()
        // GERMANY (rank 1: rich success), relay (rank 2: no history),
        // STOCKHOLM (rank 3: rich failure) - a real 3-way global order.
        val history = SeededPathHistoryStore(
            mapOf(
                germany.endpointId.value to richSuccessHistory,
                stockholm.endpointId.value to richFailureHistory,
            ),
        )
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithAllThree(), history)

        val attempts = viewModel.combinedAutoAttempts()
        assertEquals(
            listOf(
                AutoGatewaySelector.AutoConnectAttempt.DirectAttempt::class,
                AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt::class,
                AutoGatewaySelector.AutoConnectAttempt.DirectAttempt::class,
            ),
            attempts.map { it::class },
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY", "relay:${ingressId.value}", "direct:STOCKHOLM"), orderLog)
    }

    // --- E: MAX_ATTEMPTS is global across mixed candidate types ---

    @Test
    fun `E - MAX_ATTEMPTS bounds the combined sequence across Direct and Relayed together`() = runTest {
        val orderLog = mutableListOf<String>()
        val history = SeededPathHistoryStore(
            mapOf(
                germany.endpointId.value to richSuccessHistory,
                stockholm.endpointId.value to richFailureHistory,
            ),
        )
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithAllThree(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // Only 3 candidates exist in total here, well under MAX_ATTEMPTS,
        // so every one of them was tried exactly once, never more.
        assertTrue(orderLog.size <= AutoGatewaySelector.MAX_ATTEMPTS)
        assertEquals(3, orderLog.size)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
    }

    // --- F: no candidate key is attempted twice ---

    @Test
    fun `F - no candidate is dialed twice across a full exhausted combined sequence`() = runTest {
        val orderLog = mutableListOf<String>()
        val history = SeededPathHistoryStore(
            mapOf(
                germany.endpointId.value to richSuccessHistory,
                stockholm.endpointId.value to richFailureHistory,
            ),
        )
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithAllThree(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(orderLog.size, orderLog.toSet().size)
    }

    // --- G: a successful Direct attempt still uses the exact existing pinned direct snapshot/runtime path ---

    @Test
    fun `G - a successful Direct attempt after a Relayed failure still uses the exact pinned GatewayConfigSnapshot`() = runTest {
        val orderLog = mutableListOf<String>()
        // Relay ranks first (GERMANY gets a failure history), so it is
        // tried and fails, THEN Direct GERMANY is tried and succeeds.
        val history = SeededPathHistoryStore(mapOf(germany.endpointId.value to richFailureHistory))
        val transport = OrderLoggingFailNThenSucceedTransport(orderLog, hostLabels, succeedOnCall = 1)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepositoryWithGermanyAndIngress(), history)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("relay:${ingressId.value}", "direct:GERMANY"), orderLog)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        val dialedConfig = transport.configs.single()
        assertEquals(germany.awg.endpointHost, dialedConfig.config.peer.endpointHost)
        assertEquals(germany.awg.endpointPort, dialedConfig.config.peer.endpointPort)
        assertEquals(germany.awg.serverPublicKeyBase64, dialedConfig.config.peer.publicKeyBase64)
        assertTrue(dialedConfig.config.localAddresses.first().startsWith("10.77.0.5"))
    }

    // --- H: existing Manual mode and Direct-only Auto behavior remain regression-safe ---
    // (Direct-only Auto flows are already exhaustively covered by
    // MainViewModelAutoGatewayTest/MainViewModelTest, which pass unmodified
    // against this fix - see that file's own tests. This adds one direct
    // confirmation that a no-ingress manifest reduces to the exact pre-B24
    // Direct-only combined list, still executed through the same path.)

    @Test
    fun `H - a manifest with no ingress produces a Direct-only combined list and behaves exactly as pre-B24 Auto mode`() = runTest {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = germany.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Germany / Frankfurt",
                    provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort)),
                ),
            ),
        )
        val signer = Ed25519Signer()
        signer.init(true, manifestSigningKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        val signed = SignedManifest(manifest, signer.generateSignature())
        val manifestRepository = EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = manifestTrustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = signed,
            nowEpochMillis = { 2_000L },
        )

        val orderLog = mutableListOf<String>()
        val transport = OrderLoggingFailNThenSucceedTransport(orderLog, hostLabels, succeedOnCall = 1)
        val dialer = OrderLoggingDialer(orderLog) { alwaysFailingRelayOutcome(it) }
        val viewModel = newViewModel(transport, dialer, manifestRepository)

        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.all { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt })

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY"), orderLog)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(0, dialer.dialedPlans.size)
    }
}
