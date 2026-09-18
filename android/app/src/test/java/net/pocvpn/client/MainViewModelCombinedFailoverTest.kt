@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import android.content.Intent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.diagnostics.support.DiagnosticOutcome
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
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
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.smartconnect.AutoGatewayFailoverPolicy
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.VpnSessionHealth
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
    // B34 - lets a test distinguish the OLD `rejectPreflight` terminal path
    // (never touches the transport at all - see that function's own docs)
    // from the NEW `abandonAttemptWithTerminalError` path (always tears
    // down the active transport exactly once - see that function's own
    // docs) even in a scenario where BOTH paths happen to leave `_state` at
    // the SAME visible `TransportState.Error` value.
    var disconnectCallCount = 0
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
        disconnectCallCount++
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

/** Same as above but succeeds on the Nth call (1-indexed) instead of always failing. */
private class OrderLoggingFailNThenSucceedTransport(
    private val orderLog: MutableList<String>,
    private val hostLabels: Map<String, String>,
    private val succeedOnCall: Int,
    private val diagnostics: DiagnosticsStore? = null,
    private val firstFailureGate: CompletableDeferred<Unit>? = null,
    private val onSecondConnect: (() -> Unit)? = null,
    private val permissionOnSecond: Boolean = false,
) : VpnTransport {
    override val name: String = "order-logging-fail-n-then-succeed"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    val configs = mutableListOf<TransportConfig.Awg>()

    override fun preparePermissionIntent(): Intent? =
        if (permissionOnSecond && connectCallCount == 1) Intent() else null

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        val awg = config as TransportConfig.Awg
        configs += awg
        val label = hostLabels[awg.config.peer.endpointHost] ?: "direct:${awg.config.peer.endpointHost}"
        orderLog += label
        if (connectCallCount < succeedOnCall) {
            if (connectCallCount == 1 && firstFailureGate != null) {
                diagnostics?.recordError(VpnError.BackendStartFailure("gated failure"))
                stateFlow.value = TransportState.Error("gated failure")
                firstFailureGate.await()
            }
            throw RuntimeException("simulated backend start failure")
        }
        if (connectCallCount == 2) onSecondConnect?.invoke()
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

private class OrderLoggingResolver(
    private val orderLog: MutableList<String>,
    private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution,
) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        orderLog += "relay:${plan.ingressEndpointId.value}"
        return resolutionFor(plan)
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
    private fun manifestRepositoryWithAllThree(includeIngress: Boolean = true): EndpointManifestRepository {
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
            ).filter { includeIngress || EndpointRole.INGRESS !in it.roles },
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
        relayIngressResolver: RelayIngressResolver,
        manifestRepository: EndpointManifestRepository,
        pathHistoryStore: PathHistoryStore? = null,
        selectedGatewayStore: net.pocvpn.client.vpn.config.SelectedGatewayStore = FakeSelectedGatewayStore(),
        supportStore: InMemoryDiagnosticSessionStore? = null,
        supportRecorder: SupportDiagnosticsRecorder? = null,
        diagnosticsStore: DiagnosticsStore = DiagnosticsStore(),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = diagnosticsStore,
        selectedGatewayStore = selectedGatewayStore,
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        ),
        gatewayAutoModeStore = AlwaysAutoModeStoreForCombinedFailover(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepository,
        pathHistoryStore = pathHistoryStore,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressResolver = relayIngressResolver,
        supportDiagnosticsRecorder = supportRecorder ?: supportStore?.let { SupportDiagnosticsRecorder(it, "1.0", 1L) },
        supportDiagnosticsStore = supportStore,
    )

    @Test
    fun `R2 Auto diagnostics follow actual combined attempts despite a different selected gateway`() = runTest {
        val orderLog = mutableListOf<String>()
        val supportStore = InMemoryDiagnosticSessionStore()
        val history = SeededPathHistoryStore(mapOf(
            germany.endpointId.value to richSuccessHistory,
            stockholm.endpointId.value to richFailureHistory,
        ))
        val transport = OrderLoggingFailNThenSucceedTransport(orderLog, hostLabels, succeedOnCall = 2)
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(
            transport, resolver, manifestRepositoryWithAllThree(), history,
            selectedGatewayStore = FakeSelectedGatewayStore(ProductionGatewayId.STOCKHOLM),
            supportStore = supportStore,
        )
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY", "relay:${ingressId.value}", "direct:STOCKHOLM"), orderLog)
        val session = supportStore.recent().single()
        val starts = session.events.filter { it.type == DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED }
        assertEquals(listOf("frankfurt", null, "stockholm"), starts.map { it.tags["plannedEndpointId"] })
        assertTrue(starts.none { it.tags.containsKey("attemptedEndpointId") })
        assertEquals(listOf("1", "2", "3"), starts.map { it.tags["attemptOrdinal"] })
        assertEquals(ingressId.value, starts[1].tags["plannedIngressEndpointId"])
        assertEquals(germany.endpointId.value, starts[1].tags["plannedExitEndpointId"])
        assertTrue(!starts[1].tags.containsKey("attemptedIngressEndpointId"))
        assertTrue(session.events.filter { it.type == DiagnosticEventType.PATH_FAILED }.any {
            it.tags["attemptOrdinal"] == "1" && it.tags["attemptedEndpointId"] == germany.endpointId.value
        })
        assertTrue(session.events.filter { it.type == DiagnosticEventType.PATH_FAILED }.any {
            it.tags["attemptOrdinal"] == "2" && it.tags["plannedIngressEndpointId"] == ingressId.value &&
                !it.tags.containsKey("attemptedIngressEndpointId") && !it.tags.containsKey("attemptedExitEndpointId")
        })
        assertEquals(stockholm.endpointId.value,
            session.events.single { it.type == DiagnosticEventType.PATH_SUCCEEDED }.tags["attemptedEndpointId"])
    }

    private fun alwaysFailingRelayResolution(plan: RelayedExecutionPlan): RelayIngressResolution =
        RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE)

    @Test
    fun `R2 Auto candidate B remains planned during permission prompt then uses ordinal two at dial`() = runTest {
        val orderLog = mutableListOf<String>()
        val supportStore = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(supportStore, "1.0", 1L)
        val transport = OrderLoggingFailNThenSucceedTransport(
            orderLog, hostLabels, succeedOnCall = 2, permissionOnSecond = true,
        )
        val history = SeededPathHistoryStore(mapOf(
            germany.endpointId.value to richSuccessHistory,
            stockholm.endpointId.value to richFailureHistory,
        ))
        val viewModel = newViewModel(
            transport, OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) },
            manifestRepositoryWithAllThree(includeIngress = false), history,
            supportStore = supportStore, supportRecorder = recorder,
        )
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertEquals(listOf("direct:GERMANY"), orderLog)
        assertTrue(supportStore.recent().isEmpty())
        val sessionId = recorder.currentSessionId()
        assertTrue(sessionId != null)

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, transport.connectCallCount)
        assertEquals(listOf("direct:GERMANY", "direct:STOCKHOLM"), orderLog)
        val session = supportStore.recent().single()
        assertEquals(sessionId, session.sessionId)
        val starts = session.events.filter { it.type == DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED }
        assertEquals(listOf("1", "2"), starts.map { it.tags["attemptOrdinal"] })
        assertEquals(listOf("frankfurt", "stockholm"), starts.map { it.tags["plannedEndpointId"] })
        assertTrue(starts.none { it.tags.containsKey("attemptedEndpointId") })
        val dials = session.events.filter { it.type == DiagnosticEventType.TRANSPORT_START }
        assertEquals(listOf("frankfurt", "stockholm"), dials.map { it.tags["attemptedEndpointId"] })
        assertEquals(listOf("1", "2"), dials.map { it.tags["attemptOrdinal"] })
        assertEquals("frankfurt", session.events.single { it.type == DiagnosticEventType.PATH_FAILED }.tags["attemptedEndpointId"])
        for (type in listOf(DiagnosticEventType.PATH_SUCCEEDED, DiagnosticEventType.VPN_PROTECTED)) {
            assertEquals("stockholm", session.events.single { it.type == type }.tags["attemptedEndpointId"])
        }
    }

    @Test
    fun `R2 Auto support session survives Failed before and after failover bookkeeping`() = runTest {
        val orderLog = mutableListOf<String>()
        val diagnostics = DiagnosticsStore()
        val supportStore = InMemoryDiagnosticSessionStore()
        val recorder = SupportDiagnosticsRecorder(supportStore, "1.0", 1L)
        val firstFailureGate = CompletableDeferred<Unit>()
        lateinit var viewModel: MainViewModel
        var lateObservationSessionId: String? = null
        var lateObservationPersisted = false
        var lateObservationFailureEligible = false
        val transport = OrderLoggingFailNThenSucceedTransport(
            orderLog, hostLabels, succeedOnCall = 2,
            diagnostics = diagnostics, firstFailureGate = firstFailureGate,
            onSecondConnect = {
                // A's watcher has recorded failure and selected B. Replaying
                // the late Failed health observation at B's real transport
                // boundary must leave this same support session open.
                viewModel.recordFailedHealthForSupport()
                lateObservationSessionId = recorder.currentSessionId()
                lateObservationPersisted = supportStore.recent().isNotEmpty()
                lateObservationFailureEligible = AutoGatewayFailoverPolicy.isEligibleForNextCandidate(
                    viewModel.transportState.value, diagnostics.snapshot.value.lastError,
                )
            },
        )
        val history = SeededPathHistoryStore(mapOf(
            germany.endpointId.value to richSuccessHistory,
            stockholm.endpointId.value to richFailureHistory,
        ))
        viewModel = newViewModel(
            transport, OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) },
            manifestRepositoryWithAllThree(includeIngress = false), history,
            supportStore = supportStore, supportRecorder = recorder, diagnosticsStore = diagnostics,
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.sessionHealth.value is VpnSessionHealth.Failed)
        assertTrue(AutoGatewayFailoverPolicy.isEligibleForNextCandidate(viewModel.transportState.value, diagnostics.snapshot.value.lastError))
        val sessionId = recorder.currentSessionId()
        assertTrue(sessionId != null)
        assertTrue(supportStore.recent().isEmpty())
        // A's retry-eligible failure is visible while controller.connect is
        // suspended, before the failover watcher can do its bookkeeping.
        viewModel.recordFailedHealthForSupport()
        assertEquals(sessionId, recorder.currentSessionId())
        assertTrue(supportStore.recent().isEmpty())

        firstFailureGate.complete(Unit)
        testDispatcher.scheduler.runCurrent()
        assertEquals(2, transport.connectCallCount)
        assertEquals(sessionId, lateObservationSessionId)
        assertTrue(!lateObservationPersisted)
        assertTrue(lateObservationFailureEligible)
        assertEquals(listOf("direct:GERMANY", "direct:STOCKHOLM"), orderLog)
        val session = supportStore.recent().single()
        assertEquals(DiagnosticOutcome.PROTECTED, session.outcome)
        assertEquals(sessionId, session.sessionId)
        val starts = session.events.filter { it.type == DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED }
        assertEquals(listOf("1", "2"), starts.map { it.tags["attemptOrdinal"] })
        assertEquals(listOf("frankfurt", "stockholm"), starts.map { it.tags["plannedEndpointId"] })
        assertTrue(starts.none { it.tags.containsKey("attemptedEndpointId") })
        val failed = session.events.filter { it.type == DiagnosticEventType.PATH_FAILED }
        assertEquals(1, failed.size)
        assertEquals("1", failed.single().tags["attemptOrdinal"])
        assertEquals("frankfurt", failed.single().tags["attemptedEndpointId"])
        for (type in listOf(DiagnosticEventType.PATH_SUCCEEDED, DiagnosticEventType.VPN_PROTECTED)) {
            val success = session.events.single { it.type == type }
            assertEquals("2", success.tags["attemptOrdinal"])
            assertEquals("stockholm", success.tags["attemptedEndpointId"])
        }
    }

    @Test
    fun `R2 Auto exhaustion closes once with no duplicate failed attempt event`() = runTest {
        val orderLog = mutableListOf<String>()
        val supportStore = InMemoryDiagnosticSessionStore()
        val history = SeededPathHistoryStore(mapOf(
            germany.endpointId.value to richSuccessHistory,
            stockholm.endpointId.value to richFailureHistory,
        ))
        val viewModel = newViewModel(
            OrderLoggingAlwaysFailTransport(orderLog, hostLabels),
            OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) },
            manifestRepositoryWithAllThree(includeIngress = false), history,
            supportStore = supportStore,
        )
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY", "direct:STOCKHOLM"), orderLog)
        val session = supportStore.recent().single()
        assertEquals(DiagnosticOutcome.FAILED, session.outcome)
        assertEquals(listOf("1", "2"), session.events.filter { it.type == DiagnosticEventType.PATH_FAILED }.map { it.tags["attemptOrdinal"] })
    }

    @Test
    fun `R2 user disconnect closes an open Auto diagnostic session once`() = runTest {
        val orderLog = mutableListOf<String>()
        val diagnostics = DiagnosticsStore()
        val supportStore = InMemoryDiagnosticSessionStore()
        val gate = CompletableDeferred<Unit>()
        val transport = OrderLoggingFailNThenSucceedTransport(
            orderLog, hostLabels, succeedOnCall = 2, diagnostics = diagnostics, firstFailureGate = gate,
        )
        val viewModel = newViewModel(
            transport, OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) },
            manifestRepositoryWithAllThree(includeIngress = false),
            supportStore = supportStore, diagnosticsStore = diagnostics,
        )
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(supportStore.recent().isEmpty())
        viewModel.disconnect()
        gate.complete(Unit)
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY"), orderLog)
        assertEquals(DiagnosticOutcome.DISCONNECTED, supportStore.recent().single().outcome)
    }

    // --- A: Direct A fails -> Relayed B is attempted next (Relayed ranks ABOVE Direct STOCKHOLM here too - see D) ---

    @Test
    fun `A - a failing higher-ranked Direct candidate is followed by the next-ranked Relayed candidate`() = runTest {
        val orderLog = mutableListOf<String>()
        // GERMANY (Direct, rank 1: rich success history) then the relay
        // (rank 2: no history) - only two candidates exist in this manifest.
        val history = SeededPathHistoryStore(mapOf(germany.endpointId.value to richSuccessHistory))
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithGermanyAndIngress(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithGermanyAndIngress(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithAllThree(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithAllThree(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithAllThree(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithGermanyAndIngress(), history)

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
        val resolver = OrderLoggingResolver(orderLog) { alwaysFailingRelayResolution(it) }
        val viewModel = newViewModel(transport, resolver, manifestRepository)

        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.all { it is AutoGatewaySelector.AutoConnectAttempt.DirectAttempt })

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(listOf("direct:GERMANY"), orderLog)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(0, resolver.resolvedPlans.size)
    }

    // --- I: B34 - full genuine exhaustion reaches the REAL terminal-teardown path, never the old rejectPreflight ---

    /**
     * B34 - physically reproduced as a real bug (PR #53's own CHAIN_DIRECT
     * physical validation, 2026-09-04): once combined Auto genuinely
     * exhausts every admitted candidate, `attemptCombined` previously
     * reported the terminal error via `VpnController.rejectPreflight` -
     * built for "reject before this controller was ever touched" - which
     * never tears down whatever transport a real prior attempt in the SAME
     * sequence already touched. This is the production-shaped integration
     * proof requested for that fix, through the REAL
     * `MainViewModel.connect()` -> `connectAuto()` -> `attemptCombined()`
     * chain (not a hand-built candidate): Direct GERMANY, Direct STOCKHOLM,
     * and a Relayed ingress (the SAME `manifestRepositoryWithAllThree()`
     * shape test E/F already use - AMNEZIA_WG both hops, not
     * XRAY_REALITY/TLS_TCP, for the SAME reason those tests already
     * document: this MainViewModel test harness's `isXrayAvailableFor`/
     * `isXrayTlsAvailableFor` flags are only ever populated by a real
     * device-activation flow, never settable directly in a plain unit test
     * - see [AutoGatewaySelectorFairnessTest]'s own dedicated
     * REALITY/TLS_TCP-shaped production candidates test, which exercises
     * the exact requested "Direct A REALITY, Direct A TLS, Direct B
     * REALITY, Direct B TLS, Relayed" shape directly against the real
     * [AutoGatewaySelector.buildCombinedAttempts]/[AutoGatewaySelector.applyRelayFairness]
     * pipeline instead). [OrderLoggingAlwaysFailTransport.disconnectCallCount]
     * is what actually distinguishes the OLD/broken path (never calls
     * `disconnect()` at all) from the NEW/fixed one (calls it exactly once
     * per real prior attempt) - the visible `TransportState.Error` value
     * alone cannot tell them apart in this synchronous-failure transport
     * shape, since both paths happen to leave that field identical here
     * (see [net.pocvpn.client.vpn.VpnControllerTerminalTeardownTest] for
     * the real, physically-relevant Xray-Connected-then-fails shape this
     * scenario's own transport double cannot represent).
     */
    @Test
    fun `I - full exhaustion (Direct GERMANY, Direct STOCKHOLM, Relayed all fail) reaches abandonAttemptWithTerminalError, tearing down every real prior attempt`() = runTest {
        val orderLog = mutableListOf<String>()
        val transport = OrderLoggingAlwaysFailTransport(orderLog, hostLabels)
        val resolver = OrderLoggingResolver(orderLog, ::alwaysFailingRelayResolution)
        val viewModel = newViewModel(transport, resolver, manifestRepositoryWithAllThree())

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // All 3 real candidates genuinely attempted, well within the
        // production MAX_ATTEMPTS budget.
        assertEquals(3, orderLog.size)
        assertTrue(orderLog.size <= AutoGatewaySelector.MAX_ATTEMPTS)

        val state = viewModel.transportState.value
        assertTrue("expected a terminal Error, was $state", state is TransportState.Error)
        assertEquals("Automatic gateway candidates exhausted", (state as TransportState.Error).message)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)

        // The REAL distinguishing proof: every Direct attempt that actually
        // touched the transport (connect() was called on it, even though it
        // threw) was genuinely torn down via disconnect() too - the old
        // rejectPreflight path would have left this at 0.
        assertTrue(
            "expected at least one real disconnect() call proving the NEW teardown path ran, got ${transport.disconnectCallCount}",
            transport.disconnectCallCount >= 1,
        )
    }
}
