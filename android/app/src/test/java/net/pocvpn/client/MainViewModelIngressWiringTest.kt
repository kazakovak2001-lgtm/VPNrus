@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
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
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.provisioning.IngressProfileResult
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.smartconnect.ConnectionOutcomeStore
import net.pocvpn.client.relay.IngressProfileProvisioner
import net.pocvpn.client.relay.InMemoryIngressProfileStore
import net.pocvpn.client.relay.NotConfiguredRelayEndToEndProbe
import net.pocvpn.client.relay.NotProvisionedRelayIngressResolver
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.smartconnect.ProductionIngressEndpoints
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
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
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
private class IngressWiringAlwaysAutoModeStore : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

/** In-memory [ConnectionOutcomeStore] double so a test can seed real prior-attempt history. */
private class InMemoryConnectionOutcomeStore(seed: List<ConnectionOutcome> = emptyList()) : ConnectionOutcomeStore {
    private val outcomes = seed.toMutableList()
    override fun recent(): List<ConnectionOutcome> = outcomes.toList()
    override fun record(outcome: ConnectionOutcome) {
        outcomes += outcome
    }
}

/** Same stubbing shape MainViewModelRelayActivationTest's own suite already uses to prove the resolver execution boundary. */
private class IngressWiringStubResolver(private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        return resolutionFor(plan)
    }
}

/** A minimal real [VpnTransport] a [RelayIngressResolution.Resolved] can hand to the real TransportOrchestrator/VpnController path. */
private class IngressWiringFakeTransport(override val kind: TransportKind) : VpnTransport {
    override val name: String = "ingress-wiring-fake"
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = kotlinx.coroutines.flow.MutableStateFlow<TransportState>(TransportState.Disconnected)
    override fun preparePermissionIntent(): android.content.Intent? = null
    override suspend fun connect(config: net.pocvpn.client.vpn.config.TransportConfig) {
        stateFlow.value = TransportState.Connected
    }
    override suspend fun disconnect() { stateFlow.value = TransportState.Disconnected }
    override fun observeState(): kotlinx.coroutines.flow.Flow<TransportState> = stateFlow
}

/**
 * B32 - proves the actual seam PR #53's follow-up review demanded: the REAL
 * `connectAuto()`/`buildCombinedAutoRankingSnapshot()` candidate-assembly
 * flow merges [ProductionIngressEndpoints] into the SAME manifest-driven
 * discovery [AutoGatewaySelector.buildCombinedAttempts] already consumes -
 * never a second, parallel candidate source, and never a hardcoded
 * "if Stockholm then Germany" special case (the merge is a plain id-keyed
 * list union, [AutoGatewaySelector]'s own already-generic/already-tested
 * scoring decides everything from there - see [ProductionIngressEndpointsTest]
 * for proof that scoring/candidate-construction itself is correct).
 */
class MainViewModelIngressWiringTest {

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

    private fun manifestEndpointFor(gateway: net.pocvpn.client.vpn.config.ProductionGatewayDescriptor) = EndpointDescriptor(
        id = gateway.endpointId,
        roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
        region = "${gateway.displayCountry} / ${gateway.displayCity}",
        provider = gateway.provider,
        transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, gateway.awg.endpointHost, gateway.awg.endpointPort)),
    )

    /** A trusted, signed manifest naming ONLY the two REAL production gateways as ordinary GATEWAY/EXIT - exactly today's real production manifest shape - and, deliberately, NO ingress entry at all (proving the fallback catalog is what supplies it). */
    private fun realisticProductionManifest(): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                manifestEndpointFor(ProductionGatewayCatalog.GERMANY),
                manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM),
            ),
        )
        return signedRepositoryFor(manifest)
    }

    private fun signedRepositoryFor(manifest: EndpointManifest): EndpointManifestRepository {
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
        manifestRepository: EndpointManifestRepository = realisticProductionManifest(),
        clientTunnelIdentityStore: net.pocvpn.client.vpn.config.ClientTunnelIdentityStore? = FakeClientTunnelIdentityStore(
            mapOf(
                ProductionGatewayCatalog.GERMANY.id to "10.77.0.2",
                ProductionGatewayCatalog.STOCKHOLM.id to "10.77.0.3",
            ),
        ),
        transport: VpnTransport = FakeVpnTransport(),
        relayIngressResolver: RelayIngressResolver = NotProvisionedRelayIngressResolver,
        ingressProfileProvisioner: IngressProfileProvisioner? = null,
        connectionOutcomeStore: ConnectionOutcomeStore? = null,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        clientTunnelIdentityStore = clientTunnelIdentityStore,
        gatewayAutoModeStore = IngressWiringAlwaysAutoModeStore(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepository,
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressResolver = relayIngressResolver,
        relayEndToEndProbe = NotConfiguredRelayEndToEndProbe,
        ingressProfileProvisioner = ingressProfileProvisioner,
        connectionOutcomeStore = connectionOutcomeStore,
        ioDispatcher = testDispatcher,
    )

    /** No client tunnel identity for either gateway - Direct candidates are structurally excluded, so the merged Stockholm relay is the ONLY combined attempt, guaranteeing it is the one actually dialed. */
    private fun relayOnlyClientTunnelIdentityStore() = FakeClientTunnelIdentityStore(emptyMap())

    // --- 1: the merge helper itself ---

    @Test
    fun `mergedIngressAwareEndpoints adds the ProductionIngressEndpoints fallback when the manifest does not name that id`() {
        val viewModel = newViewModel()
        val manifestOnly = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY), manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM))

        val merged = viewModel.mergedIngressAwareEndpoints(manifestOnly)

        assertTrue(merged.any { it.id == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID })
        assertSame(ProductionIngressEndpoints.STOCKHOLM, merged.first { it.id == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID })
        // Everything the manifest itself named is still present, untouched.
        assertTrue(merged.containsAll(manifestOnly))
    }

    @Test
    fun `mergedIngressAwareEndpoints never duplicates an id the manifest already names - the SIGNED manifest entry wins, never the fallback`() {
        val viewModel = newViewModel()
        // A hypothetical FUTURE signed manifest that already names the ingress
        // id itself, with DIFFERENT data than the hardcoded fallback (a
        // different relay target) - proves precedence, not just presence.
        val signedIngressEntry = EndpointDescriptor(
            id = ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID,
            roles = setOf(EndpointRole.INGRESS),
            region = "signed-manifest-region",
            provider = "signed-manifest-provider",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.99", 9999)),
            relayTo = ProductionGatewayCatalog.GERMANY.endpointId,
        )
        val manifestEndpoints = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY), signedIngressEntry)

        val merged = viewModel.mergedIngressAwareEndpoints(manifestEndpoints)

        val matches = merged.filter { it.id == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID }
        assertEquals("must not produce a duplicate endpoint id", 1, matches.size)
        assertSame("the SIGNED manifest's own descriptor must win over the hardcoded fallback", signedIngressEntry, matches.single())
    }

    @Test
    fun `mergedIngressAwareEndpoints with an empty manifest still supplies the fallback ingress`() {
        val viewModel = newViewModel()

        val merged = viewModel.mergedIngressAwareEndpoints(emptyList())

        assertEquals(ProductionIngressEndpoints.all, merged)
    }

    // --- 2/3: the real connectAuto()-facing ranking flow ---

    @Test
    fun `combinedAutoAttempts contains a real Relayed CHAIN_DIRECT Stockholm-ingress-to-Germany-exit candidate from the realistic production manifest`() {
        val viewModel = newViewModel()

        val attempts = viewModel.combinedAutoAttempts()

        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>()
        assertTrue("expected at least one relayed attempt, got: $attempts", relayed.isNotEmpty())
        val stockholmToGermany = relayed.map { it.candidate }.firstOrNull {
            it.ingressEndpointId == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID && it.exitEndpointId == ProductionGatewayCatalog.GERMANY.endpointId
        }
        assertNotNull("expected a Stockholm-ingress -> Germany-exit relayed candidate", stockholmToGermany)
    }

    @Test
    fun `DIRECT Stockholm and DIRECT Germany candidates remain present alongside the merged relay candidate`() {
        val viewModel = newViewModel()

        val attempts = viewModel.combinedAutoAttempts()

        val directEndpointIds = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.DirectAttempt>().map { it.candidate.endpointId }.toSet()
        assertTrue(ProductionGatewayCatalog.GERMANY.endpointId in directEndpointIds)
        assertTrue(ProductionGatewayCatalog.STOCKHOLM.endpointId in directEndpointIds)
    }

    @Test
    fun `no duplicate relayed candidate appears when an equivalent signed-manifest ingress entry is already present`() {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                manifestEndpointFor(ProductionGatewayCatalog.GERMANY),
                manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM),
                // The SAME ingress id/topology the fallback catalog would also supply.
                ProductionIngressEndpoints.STOCKHOLM,
            ),
        )
        val viewModel = newViewModel(manifestRepository = signedRepositoryFor(manifest))

        val attempts = viewModel.combinedAutoAttempts()
        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>()
        val stockholmToGermanyCount = relayed.count {
            it.candidate.ingressEndpointId == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID &&
                it.candidate.exitEndpointId == ProductionGatewayCatalog.GERMANY.endpointId &&
                it.candidate.ingressTransport == TransportKind.XRAY_REALITY
        }
        assertEquals("must appear exactly once, never duplicated by the fallback merge", 1, stockholmToGermanyCount)
    }

    @Test
    fun `an unknown manifest-named ingress id (not in ProductionIngressEndpoints) never becomes spuriously eligible, even with a valid relayTo`() {
        // The registry-narrowing fix (B32 round 2): XRAY_REALITY availability
        // for a non-gateway endpoint id is gated on membership in
        // ProductionIngressEndpoints.all specifically, never "any id absent
        // from ProductionGatewayCatalog" - this manifest-only ingress (valid
        // shape, valid relayTo, otherwise indistinguishable from a real one)
        // must NOT be treated as dial-capable just because it is unknown.
        val unknownIngress = EndpointDescriptor(
            id = EndpointId("some-unrelated-ingress-nobody-reviewed"),
            roles = setOf(EndpointRole.INGRESS),
            region = "nowhere",
            provider = "unknown",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.200", 4433)),
            relayTo = ProductionGatewayCatalog.GERMANY.endpointId,
        )
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY), manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM), unknownIngress),
        )
        val viewModel = newViewModel(manifestRepository = signedRepositoryFor(manifest))

        val attempts = viewModel.combinedAutoAttempts()

        assertFalse(
            "an id absent from the reviewed ProductionIngressEndpoints catalog must never be reported dial-capable",
            attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().any { it.candidate.ingressEndpointId == unknownIngress.id },
        )
        // The real Stockholm-ingress fallback merge still worked despite the unrelated unknown entry.
        assertTrue(attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().any { it.candidate.ingressEndpointId == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID })
    }

    @Test
    fun `an ingress entry with no relayTo target fails closed - no relayed candidate, no crash`() {
        val conflicting = EndpointDescriptor(
            id = EndpointId("conflicting-ingress"),
            roles = setOf(EndpointRole.INGRESS),
            region = "nowhere",
            provider = "unknown",
            transports = listOf(EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.77", 1234)),
            relayTo = null,
        )
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(manifestEndpointFor(ProductionGatewayCatalog.GERMANY), manifestEndpointFor(ProductionGatewayCatalog.STOCKHOLM), conflicting),
        )
        val viewModel = newViewModel(manifestRepository = signedRepositoryFor(manifest))

        val attempts = viewModel.combinedAutoAttempts()

        assertFalse(attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().any { it.candidate.ingressEndpointId == conflicting.id })
        // The real Stockholm-ingress fallback merge still worked despite the unrelated conflicting entry.
        assertTrue(attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>().any { it.candidate.ingressEndpointId == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID })
    }

    // --- 4: the relayed winner reaches the SAME execution boundary Direct already uses ---

    @Test
    fun `a Relayed winner reaches the existing execution boundary and fails closed with the typed EXECUTION_NOT_IMPLEMENTED category - no debug-force path needed`() = kotlinx.coroutines.test.runTest {
        // No client tunnel identity provisioned for EITHER gateway - Direct
        // candidates are structurally excluded (buildCandidates requires a
        // non-blank clientTunnelIp), so the ONLY combined attempt available
        // is the merged Stockholm-ingress relay, guaranteeing it is the one
        // actually dialed - proving requirement 7 (the relayed candidate
        // reaches TransportOrchestrator's real execution boundary) through
        // the REAL connectAuto()/attemptCombined() flow, never a debug-force
        // or manual-profile shortcut (requirement 8).
        val viewModel = newViewModel(clientTunnelIdentityStore = FakeClientTunnelIdentityStore(emptyMap()))
        val onlyAttempt = viewModel.combinedAutoAttempts().single()
        assertTrue(onlyAttempt is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertFalse(viewModel.transportState.value is net.pocvpn.client.vpn.TransportState.Connected)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.lastFailureReason?.contains("EXECUTION_NOT_IMPLEMENTED") == true)
    }

    // --- 5: the ACTUAL production dependency wiring (RelayIngressResolverImpl/
    // IngressProfileProvisioner/FileIngressProfileStore/POST /v1/ingress-profile,
    // all real and already wired by MainViewModel.Factory.create ->
    // RelayCompositionFactory.build - see RelayCompositionFactoryTest for proof
    // Factory selects these, never the NotProvisioned/NotConfigured
    // stand-ins). Pre-B32 this could only be exercised against a HAND-BUILT
    // RelayAttemptCandidate (see MainViewModelRelayActivationTest's own docs:
    // "a genuinely ELIGIBLE XRAY_REALITY relayed candidate cannot be produced
    // through [combinedAutoAttempts/connect()] in this test harness"). B32's
    // buildTransportRegistry fix lifts exactly that restriction - these tests
    // exercise the identical resolver contract through the REAL public
    // connectAuto()/connect() ranking pipeline instead of a hand-built
    // candidate, closing that gap for the ACTUAL discovered Stockholm ingress.

    private fun stockholmSuccessResult(
        serverAddress: String = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)!!.host,
        serverPort: Int = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)!!.port,
        ingressEndpointId: String = ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID.value,
    ) = IngressProfileResult.Success(
        ingressEndpointId = ingressEndpointId,
        ingressKind = net.pocvpn.client.reachability.IngressKind.DIRECT_IP,
        serverAddress = serverAddress,
        serverPort = serverPort,
        uuid = "11111111-1111-1111-1111-111111111111",
        serverName = "www.bing.com",
        fingerprint = "chrome",
        flow = "",
        realityPublicKey = "A".repeat(43),
        shortId = "ab",
        isRealityShaped = true,
        profileVersion = 1,
        issuedAtEpochSeconds = 1_000L,
        expiresAtEpochSeconds = null,
        probeUrl = "https://152.70.43.1/v1/relay-health",
        probeToken = "test-token",
    )

    @Test
    fun `connectAuto ranks the real Stockholm CHAIN_DIRECT candidate and dispatches it to relayIngressResolver_resolve - no premature transport connect while unprovisioned`() = kotlinx.coroutines.test.runTest {
        val resolver = IngressWiringStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(clientTunnelIdentityStore = relayOnlyClientTunnelIdentityStore(), relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, resolver.resolvedPlans.size)
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, resolver.resolvedPlans.single().ingressEndpointId)
        assertEquals(TransportKind.XRAY_REALITY, resolver.resolvedPlans.single().ingressTransport)
        // Activation-required (PROFILE_NOT_PROVISIONED is activation-fixable) - a
        // real prompt is raised, and the combined sequence PAUSES rather than
        // silently exhausting or falling through to a premature connect.
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, viewModel.relayActivationNeeded.value?.ingressEndpointId)
        assertFalse(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `an activation-INfixable category (e_g_ INGRESS_UNREACHABLE) never raises the activation prompt - fails closed and exhausts immediately`() = kotlinx.coroutines.test.runTest {
        val resolver = IngressWiringStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.INGRESS_UNREACHABLE) }
        val viewModel = newViewModel(clientTunnelIdentityStore = relayOnlyClientTunnelIdentityStore(), relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertNull(viewModel.relayActivationNeeded.value)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
        assertFalse(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `a successful real activateIngress() persists the correct profile for stockholm-ingress-1 and retries the SAME pending candidate`() = kotlinx.coroutines.test.runTest {
        val resolver = IngressWiringStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> fetchCount++; stockholmSuccessResult() })
        val viewModel = newViewModel(clientTunnelIdentityStore = relayOnlyClientTunnelIdentityStore(), relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(1, resolver.resolvedPlans.size)

        viewModel.activateIngress("real-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, fetchCount)
        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
        val saved = store.getProfileOrNull(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID)
        assertNotNull("the profile must be persisted under stockholm-ingress-1's own endpoint id", saved)
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, saved!!.ingressEndpointId)
        assertEquals(TransportKind.XRAY_REALITY, saved.transport)
        // Requirement 5 - the retry resolves the SAME pending plan, never a freshly ranked one.
        assertEquals(2, resolver.resolvedPlans.size)
        assertEquals(resolver.resolvedPlans[0].historyPathId, resolver.resolvedPlans[1].historyPathId)
        assertEquals(resolver.resolvedPlans[0].ingressBinding, resolver.resolvedPlans[1].ingressBinding)
    }

    @Test
    fun `a successful provision() through the real IngressProfileProvisioner produces a profile RelayIngressResolverImpl's own match check accepts`() = kotlinx.coroutines.test.runTest {
        // Proves requirement 6's data contract against the REAL
        // IngressProfileProvisioner (the real /v1/ingress-profile client
        // path) and IngressClientProfile.matches (the exact check
        // RelayIngressResolverImpl.resolve gates Resolved on - see that
        // class, read directly above) without constructing
        // RelayIngressResolverImpl itself: its resolve() success branch
        // additionally writes through XrayProfileRepositoryFactory's real
        // AndroidKeyStore-backed encryptor, a documented, pre-existing
        // incompatibility with this project's plain-JVM unit test
        // environment (see RelayCompositionFactoryTest's own docs, which
        // is why even THAT test only Robolectric-covers RelayCompositionFactory.build,
        // never a full resolve() call) - see RelayIngressResolverImplTest
        // (Robolectric) for the early-return branches (PROFILE_NOT_PROVISIONED/
        // PROFILE_MISMATCH/PROFILE_EXPIRED) that don't touch Keystore at all.
        val plan = RelayedExecutionPlan.from(
            AutoGatewaySelector.RelayAttemptCandidate(
                ingressEndpointId = ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID,
                exitEndpointId = ProductionGatewayCatalog.GERMANY.endpointId,
                ingressTransport = TransportKind.XRAY_REALITY,
                exitTransport = TransportKind.XRAY_REALITY,
                ingressBinding = ProductionIngressEndpoints.STOCKHOLM.bindingFor(TransportKind.XRAY_REALITY)!!,
                exitBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 443),
                ingressKind = net.pocvpn.client.reachability.IngressKind.DIRECT_IP,
                ingressRegion = "Stockholm", exitRegion = "Frankfurt",
                score = 1_000L, reasons = listOf("test"),
                historyPathId = "${ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID.value}:DIRECT_IP:XRAY_REALITY->frankfurt:XRAY_REALITY",
            ),
        )
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(store, fetchIngressProfile = { _, _, _, _ -> stockholmSuccessResult() })

        val outcome = provisioner.provision(plan.ingressEndpointId, plan.ingressBinding, plan.ingressTransport, plan.ingressKind, "pub-key", "cred")

        assertTrue(outcome is IngressActivationOutcome.Saved)
        val stored = store.getProfileOrNull(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID)
        assertNotNull(stored)
        assertTrue("a real provisioned profile must be accepted by RelayIngressResolverImpl's own match check", stored!!.matches(plan))
        assertFalse(stored.isExpired(System.currentTimeMillis()))
        assertEquals(ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID, stored.ingressEndpointId)
        assertEquals(TransportKind.XRAY_REALITY, stored.transport)
    }

    // --- PR #58 field-test fix: a different endpoint's real Direct
    // XRAY_REALITY failure history must never exclude the relay candidate ---

    @Test
    fun `the real production Stockholm CHAIN_DIRECT candidate survives combinedAutoAttempts even after Germany's own Direct XRAY_REALITY dial has failed twice`() {
        // Reproduces the exact 2026-09 Russia field-test bug through the
        // REAL public connectAuto()-facing pipeline (never a hand-built
        // AutoConnectAttempt/RelayAttemptCandidate): Germany's own Direct
        // XRAY_REALITY dial correctly recording two consecutive FAILUREs
        // (a physically blocked port, 2053) used to flip the SHARED
        // transportHealthFor(XRAY_REALITY) bucket to UNREACHABLE, which
        // then made the completely separate, never-yet-dialed
        // stockholm-ingress-1 XRAY_REALITY candidate (port 2093) ineligible
        // too via PathScorer's own "UNREACHABLE unless a hop is confirmed
        // REACHABLE" rule - dropping CHAIN_DIRECT out of ranking before it
        // was ever attempted (see AutoGatewaySelector.buildRelayedCandidates'
        // own docs for the full story).
        val outcomeStore = InMemoryConnectionOutcomeStore(
            seed = listOf(
                ConnectionOutcome(
                    transport = TransportKind.XRAY_REALITY,
                    gatewayId = ProductionGatewayCatalog.GERMANY.endpointId.value,
                    result = ConnectionOutcomeResult.FAILURE,
                    handshakeDurationMs = null,
                    errorCategory = ConnectionErrorCategory.HANDSHAKE_TIMEOUT,
                    timestampEpochMillis = 1_000L,
                ),
                ConnectionOutcome(
                    transport = TransportKind.XRAY_REALITY,
                    gatewayId = ProductionGatewayCatalog.GERMANY.endpointId.value,
                    result = ConnectionOutcomeResult.FAILURE,
                    handshakeDurationMs = null,
                    errorCategory = ConnectionErrorCategory.HANDSHAKE_TIMEOUT,
                    timestampEpochMillis = 2_000L,
                ),
            ),
        )
        val viewModel = newViewModel(connectionOutcomeStore = outcomeStore)

        // Sanity check the seeded history actually poisons the SHARED,
        // kind-wide bucket the way the physical bug depended on - if this
        // assertion ever stops holding, the test below would pass for the
        // wrong reason.
        assertEquals(
            net.pocvpn.client.transport.TransportHealthState.UNREACHABLE,
            viewModel.transportHealth().getValue(TransportKind.XRAY_REALITY).state,
        )

        val attempts = viewModel.combinedAutoAttempts()

        val relayed = attempts.filterIsInstance<AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt>()
        val stockholmToGermany = relayed.map { it.candidate }.firstOrNull {
            it.ingressEndpointId == ProductionIngressEndpoints.STOCKHOLM_INGRESS_ID && it.exitEndpointId == ProductionGatewayCatalog.GERMANY.endpointId
        }
        assertNotNull(
            "the Stockholm CHAIN_DIRECT candidate must survive ranking despite Germany's unrelated Direct XRAY_REALITY failures",
            stockholmToGermany,
        )
    }

    @Test
    fun `no secret fields (uuid, private key, activation credential) ever appear in autoGatewayDiagnostics text for a relay attempt`() = kotlinx.coroutines.test.runTest {
        val resolver = IngressWiringStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(clientTunnelIdentityStore = relayOnlyClientTunnelIdentityStore(), relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        val reason = viewModel.autoGatewayDiagnostics.value?.lastFailureReason.orEmpty()
        assertFalse(reason.contains("11111111-1111-1111-1111-111111111111"))
        assertFalse(reason.contains("real-credential"))
        assertFalse(reason.lowercase().contains("privatekey"))
    }
}
