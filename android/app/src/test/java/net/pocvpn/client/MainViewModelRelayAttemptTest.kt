@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

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
import net.pocvpn.client.relay.IngressClientProfile
import net.pocvpn.client.relay.NotConfiguredRelayEndToEndProbe
import net.pocvpn.client.relay.NotProvisionedRelayIngressResolver
import net.pocvpn.client.relay.RelayEndToEndProbe
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
import net.pocvpn.client.relay.RelayProbeResult
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.relay.fakeIngressClientProfile
import net.pocvpn.client.vpn.VpnSessionHealth
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.transport.TransportCapabilities
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
import android.content.Intent

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

/** A resolver stub that always returns the given resolution and records every plan it was asked to resolve. */
private class StubRelayIngressResolver(private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        return resolutionFor(plan)
    }
}

/** B25 - a probe stub that always returns the given result and records every (plan, profile) it was asked to probe. */
private class StubRelayEndToEndProbe(private val resultFor: (RelayedExecutionPlan, IngressClientProfile) -> RelayProbeResult) : RelayEndToEndProbe {
    val probedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun probe(plan: RelayedExecutionPlan, profile: IngressClientProfile): RelayProbeResult {
        probedPlans += plan
        return resultFor(plan, profile)
    }
}

/**
 * B24 review fix (PR #38, round 3) test fixture - a real [VpnTransport] a
 * [RelayIngressResolution.Resolved] can hand to the EXISTING
 * TransportOrchestrator/VpnController path, always failing its handshake -
 * proves a Resolved resolution is dialed through the real single-owner
 * path, never a second one.
 */
private class AlwaysFailingIngressTransport : VpnTransport {
    override val name: String = "always-failing-ingress"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set

    override fun preparePermissionIntent(): Intent? = null
    override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
        connectCallCount++
        throw RuntimeException("simulated ingress handshake failure")
    }
    override suspend fun disconnect() { stateFlow.value = TransportState.Disconnected }
    override fun observeState(): Flow<TransportState> = stateFlow
}

/** Same as above but reaches Connected - proves even a REAL, controller-observed Connected state for a relay's ingress hop is never recorded as relay success (task requirement 8). */
private class HandshakeSucceedingIngressTransport : VpnTransport {
    override val name: String = "handshake-succeeding-ingress"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)

    override fun preparePermissionIntent(): Intent? = null
    override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() { stateFlow.value = TransportState.Disconnected }
    override fun observeState(): Flow<TransportState> = stateFlow
}

/**
 * B24 review fix (PR #38, round 3 - ownership boundary) - proves the real
 * client execution integration converges into the EXISTING
 * TransportOrchestrator/VpnController/VpnService ownership path: a resolved
 * relay transport is dialed through that SAME path (never a second
 * controller), the outcome is recorded under the FULL relayed
 * historyPathId, a real Connected state for the ingress hop is STILL never
 * recorded as relay success, and bounded retry never mutates a candidate's
 * own pinned identity.
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
        relayIngressResolver: RelayIngressResolver = NotProvisionedRelayIngressResolver,
        relayEndToEndProbe: RelayEndToEndProbe = NotConfiguredRelayEndToEndProbe,
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
        relayIngressResolver = relayIngressResolver,
        relayEndToEndProbe = relayEndToEndProbe,
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
    fun `a NotProvisioned relay resolution records history under the full relayed historyPathId, never under either hop's endpoint id alone`() = runTest {
        val store = RecordingPathHistoryStore()
        val resolver = StubRelayIngressResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE) }
        val viewModel = newViewModel(relayIngressResolver = resolver, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(store.records.isNotEmpty())
        assertTrue(store.records.all { it.pathId.contains("->") })
        assertFalse(store.records.any { it.pathId == ingressId.value })
        assertFalse(store.records.any { it.pathId == ProductionGatewayCatalog.GERMANY.endpointId.value })
        assertFalse(store.records.first().success)
    }

    @Test
    fun `a resolved relay transport that fails its handshake also records history under the full relayed historyPathId`() = runTest {
        val store = RecordingPathHistoryStore()
        // B24 review fix (round 3) test note - the fake transport is
        // constructed ONCE and passed as BOTH this ViewModel's base
        // `transport` AND what the resolver hands back: VpnController's
        // switchActiveTransport() only freshly (re-)subscribes to a
        // transport's own observeState() when the INSTANCE actually
        // changes (see MainViewModelAutoGatewayTest's own
        // FailNTimesThenSucceedTransport note on this) - reusing the
        // already-attached instance here avoids a benign but confusing
        // replay-on-subscribe race with the authoritative
        // doConnectAttempt() catch-block setState(Error), exactly like
        // every other real transport double in this codebase already does.
        val fakeTransport = AlwaysFailingIngressTransport()
        val resolver = StubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(fakeTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val viewModel = newViewModel(transport = fakeTransport, relayIngressResolver = resolver, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // B24 review fix, round 3 note: because a Resolved relay attempt
        // now genuinely reuses the real VpnController.connect() path,
        // VpnController's OWN pre-existing generic recordPathHistory ALSO
        // writes its own entry, keyed by the bare ingress endpoint id (a
        // real, harmless, single-hop "was the ingress itself reachable"
        // fact - see PROJECT_ARCHITECTURE.md's own note on this). This
        // assertion is scoped to the COMPOSITE historyPathId specifically -
        // the ONLY key relay scoring (AutoGatewaySelector.buildRelayedCandidates)
        // ever reads - proving THAT record (MainViewModel's own
        // recordRelayOutcome write) is correctly scoped and reports failure.
        val relayRecords = store.records.filter { it.pathId.contains("->") }
        assertTrue(relayRecords.isNotEmpty())
        assertFalse(relayRecords.first().success)
    }

    // --- Task requirement C/H (ownership boundary): a real Connected ingress transport still never claims relay success ---

    @Test
    fun `a resolved ingress transport reaching a real Connected state is STILL never recorded as relay success under the composite historyPathId`() = runTest {
        val store = RecordingPathHistoryStore()
        val fakeTransport = HandshakeSucceedingIngressTransport()
        val resolver = StubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(fakeTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val viewModel = newViewModel(transport = fakeTransport, relayIngressResolver = resolver, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // The underlying transport genuinely reached Connected - this is
        // real, not faked - but MainViewModel's own relay-outcome
        // bookkeeping (the composite-historyPathId record relay scoring
        // actually reads) must never call that "success" for a relay: no
        // end-to-end data-plane proof exists yet (RelayReadinessStage
        // .UPSTREAM_EXIT_HANDSHAKE_OK/.END_TO_END_DATA_PLANE_OK are not
        // reachable from a client-only handshake observation). See the
        // previous test's own note on why a SEPARATE, single-hop
        // VpnController-generic record may legitimately show success
        // alongside this one - that key is never consulted for relay
        // health/scoring.
        val relayRecords = store.records.filter { it.pathId.contains("->") }
        assertTrue(relayRecords.isNotEmpty())
        assertFalse("a relay attempt must never record success under its composite historyPathId from ingress handshake alone", relayRecords.any { it.success })
    }

    // --- Task requirement D: production unprovisioned relay remains fail-closed ---

    @Test
    fun `NotProvisionedRelayIngressResolver (the production default) never claims relay success - connect() fails closed`() = runTest {
        val viewModel = newViewModel()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is TransportState.Connected)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.lastFailureReason?.contains("EXECUTION_NOT_IMPLEMENTED") == true)
    }

    @Test
    fun `a RELAY_AUTH_FAILED resolver-level rejection fails closed and surfaces the exact typed category`() = runTest {
        val resolver = StubRelayIngressResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.RELAY_AUTH_FAILED) }
        val viewModel = newViewModel(relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is TransportState.Connected)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
        val reason = viewModel.autoGatewayDiagnostics.value?.lastFailureReason
        assertTrue(reason?.contains("RELAY_AUTH_FAILED") == true)
    }

    // --- Task requirement K: bounded retry, never mutates the candidate's own exit/bindings ---

    @Test
    fun `a persistently failing relay is resolved a BOUNDED number of times, always with the SAME pinned ingress and exit bindings`() = runTest {
        val resolver = StubRelayIngressResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE) }
        val viewModel = newViewModel(relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // With only ONE relay candidate available (no Direct alternative in
        // this manifest), the shared combined budget must resolve it AT MOST
        // once - a persistently failing single candidate is never retried
        // in a loop (task's own "no unbounded retries").
        assertEquals(1, resolver.resolvedPlans.size)
        val plan = resolver.resolvedPlans.single()
        assertEquals(ingressId, plan.ingressEndpointId)
        assertEquals(ProductionGatewayCatalog.GERMANY.endpointId, plan.exitEndpointId)
    }

    // --- B25 task C/B/M#3 - a real end-to-end probe success is the ONLY way to reach RelayProtected ---

    @Test
    fun `a genuine end-to-end probe success promotes the relayed session to RelayProtected and records a real Success`() = runTest {
        val store = RecordingPathHistoryStore()
        val fakeTransport = HandshakeSucceedingIngressTransport()
        val resolver = StubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(fakeTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = StubRelayEndToEndProbe { _, _ -> RelayProbeResult.Success }
        val viewModel = newViewModel(transport = fakeTransport, relayIngressResolver = resolver, relayEndToEndProbe = probe, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, probe.probedPlans.size)
        assertEquals(VpnSessionHealth.RelayProtected, viewModel.sessionHealth.value)
        val relayRecords = store.records.filter { it.pathId.contains("->") }
        assertTrue("a genuine end-to-end probe success must record a real Success under the composite historyPathId", relayRecords.any { it.success })
    }

    @Test
    fun `a failed end-to-end probe never shows RelayProtected, fails closed, and advances the combined attempt budget`() = runTest {
        val store = RecordingPathHistoryStore()
        val fakeTransport = HandshakeSucceedingIngressTransport()
        val resolver = StubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(fakeTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val probe = StubRelayEndToEndProbe { _, _ -> RelayProbeResult.Failure(RelayFailureCategory.UPSTREAM_EXIT_UNREACHABLE, "simulated") }
        val viewModel = newViewModel(transport = fakeTransport, relayIngressResolver = resolver, relayEndToEndProbe = probe, pathHistoryStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.sessionHealth.value !is VpnSessionHealth.RelayProtected)
        val relayRecords = store.records.filter { it.pathId.contains("->") }
        assertTrue(relayRecords.isNotEmpty())
        assertFalse(relayRecords.any { it.success })
        assertTrue(viewModel.autoGatewayDiagnostics.value?.lastFailureReason?.contains("UPSTREAM_EXIT_UNREACHABLE") == true)
        // Only one relay candidate exists in this manifest - the combined
        // budget genuinely advanced past it (exhausted), never stuck
        // re-showing a stale Connected/Protected state for the failed attempt.
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
    }

    @Test
    fun `NotConfiguredRelayEndToEndProbe (the production default) never fabricates RelayProtected for a real ingress handshake`() = runTest {
        val fakeTransport = HandshakeSucceedingIngressTransport()
        val resolver = StubRelayIngressResolver { plan -> RelayIngressResolution.Resolved(fakeTransport, TransportKind.AMNEZIA_WG, fakeIngressClientProfile(plan)) }
        val viewModel = newViewModel(transport = fakeTransport, relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.sessionHealth.value !is VpnSessionHealth.RelayProtected)
    }
}
