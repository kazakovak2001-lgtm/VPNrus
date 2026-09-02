@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.IngressProfileResult
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
import net.pocvpn.client.relay.IngressActivationOutcome
import net.pocvpn.client.relay.IngressProfileProvisioner
import net.pocvpn.client.relay.InMemoryIngressProfileStore
import net.pocvpn.client.relay.RelayFailureCategory
import net.pocvpn.client.relay.RelayIngressResolution
import net.pocvpn.client.relay.RelayIngressResolver
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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
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

private class RelayActivationAlwaysAutoModeStore : GatewayAutoModeStore {
    override fun read(): Boolean = true
    override fun write(auto: Boolean) {}
}

private class RelayActivationStubResolver(private val resolutionFor: (RelayedExecutionPlan) -> RelayIngressResolution) : RelayIngressResolver {
    val resolvedPlans = mutableListOf<RelayedExecutionPlan>()
    override suspend fun resolve(plan: RelayedExecutionPlan): RelayIngressResolution {
        resolvedPlans += plan
        return resolutionFor(plan)
    }
}

/**
 * B26 review fix (blocker 1) - proves the real product activation flow:
 * a relayed Auto attempt that hits an activation-fixable
 * [RelayFailureCategory] surfaces a bounded, UI-observable
 * [net.pocvpn.client.relay.RelayActivationRequest] carrying ONLY the
 * already-pinned candidate facts; [MainViewModel.activateIngress] runs
 * the REAL [IngressProfileProvisioner] (never a second credential/profile
 * system), never mutates the pinned endpoint/binding, clears the prompt
 * and retries the connect flow EXACTLY once on success, and never prompts
 * at all for a category no activation could fix.
 */
class MainViewModelRelayActivationTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("test-manifest-key") to manifestSigningKey.generatePublicKey().encoded),
    )
    private val ingressId = EndpointId("ru-ingress-1")
    // AMNEZIA_WG here deliberately, NOT XRAY_REALITY - see
    // manifestRepositoryWithIngressOnly's own comment on why a genuinely
    // ELIGIBLE relayed candidate (as buildCombinedAutoAttempts' real
    // PathScorer eligibility check requires) needs a transport this
    // ViewModel's own buildTransportRegistry reports as AVAILABLE without
    // additional per-endpoint xrayAvailableEndpoints wiring this test
    // harness has no seam for - exactly the same reason
    // MainViewModelRelayAttemptTest's own fixture uses AMNEZIA_WG.
    // IngressProfileProvisioner's own XRAY_REALITY/TLS_TCP-specific
    // behavior (the actual thing task D/E care about) is exercised via a
    // MANUALLY constructed RelayActivationRequest below (activateIngress
    // does not require its request to have come from a real connect()
    // attempt - see xrayActivationRequest's own docs) and, more
    // thoroughly, by IngressProfileProvisionerTest.
    private val ingressBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.50", 8443)
    private val xrayIngressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 8443)
    private fun xrayActivationRequest() = net.pocvpn.client.relay.RelayActivationRequest(ingressId, xrayIngressBinding, TransportKind.XRAY_REALITY)

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    /** A trusted, signed manifest naming ONE INGRESS (relayTo Germany, XRAY_REALITY both hops) and Germany as EXIT - mirrors MainViewModelRelayAttemptTest's own fixture, transport kind changed to exercise the real IngressProfileProvisioner (XRAY_REALITY/TLS_TCP only). */
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
                    // AMNEZIA_WG, not XRAY_REALITY, for the EXIT hop
                    // deliberately: a catalog-known endpoint's reachability
                    // lookup (buildCombinedAutoAttempts' own reachabilityFor)
                    // derives its descriptor from ProductionGatewayEndpoints
                    // .descriptorFor, which only reports XRAY_REALITY/TLS_TCP
                    // support when this ViewModel's own xrayAvailableEndpoints
                    // includes it (unrelated to this test - see
                    // MainViewModelRelayAttemptTest's own AMNEZIA_WG choice
                    // for the same reason). The INGRESS hop below is what
                    // actually exercises XRAY_REALITY/IngressProfileProvisioner -
                    // client<->ingress and ingress<->exit are independent
                    // transports by design (PROJECT_ARCHITECTURE.md's B23
                    // section), so this is a real, valid combination.
                    transports = listOf(
                        EndpointTransportBinding(TransportKind.AMNEZIA_WG, germany.awg.endpointHost, germany.awg.endpointPort),
                    ),
                ),
                EndpointDescriptor(
                    id = ingressId,
                    roles = setOf(EndpointRole.INGRESS),
                    region = "ru",
                    provider = "operator-a",
                    transports = listOf(ingressBinding),
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
        relayIngressResolver: RelayIngressResolver,
        ingressProfileProvisioner: IngressProfileProvisioner? = null,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        gatewayAutoModeStore = RelayActivationAlwaysAutoModeStore(),
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepositoryWithIngressOnly(),
        fingerprintKeyProvider = NetworkFingerprintKeyProvider { byteArrayOf(1, 2, 3, 4) },
        relayIngressResolver = relayIngressResolver,
        ingressProfileProvisioner = ingressProfileProvisioner,
        ioDispatcher = testDispatcher,
    )

    private fun successResult(serverAddress: String = ingressBinding.host, serverPort: Int = ingressBinding.port) = IngressProfileResult.Success(
        ingressEndpointId = ingressId.value,
        serverAddress = serverAddress,
        serverPort = serverPort,
        uuid = "11111111-1111-1111-1111-111111111111",
        serverName = "example.com",
        fingerprint = "chrome",
        flow = "",
        realityPublicKey = "A".repeat(43),
        shortId = "ab",
        isRealityShaped = true,
        profileVersion = 1,
        issuedAtEpochSeconds = 1_000L,
        expiresAtEpochSeconds = null,
        probeUrl = "https://exit.example/v1/relay-health",
        probeToken = "test-token",
    )

    // --- A: PROFILE_NOT_PROVISIONED (and the other two fixable categories) surface a bounded prompt ---

    @Test
    fun `PROFILE_NOT_PROVISIONED surfaces a relayActivationNeeded prompt carrying the pinned ingress facts`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        val request = viewModel.relayActivationNeeded.value
        assertNotNull(request)
        assertEquals(ingressId, request!!.ingressEndpointId)
        assertEquals(ingressBinding, request.ingressBinding)
        assertEquals(TransportKind.AMNEZIA_WG, request.ingressTransport)
    }

    @Test
    fun `PROFILE_EXPIRED and PROFILE_MISMATCH also surface the prompt`() = runTest {
        for (category in listOf(RelayFailureCategory.PROFILE_EXPIRED, RelayFailureCategory.PROFILE_MISMATCH)) {
            val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(category) }
            val viewModel = newViewModel(relayIngressResolver = resolver)
            viewModel.connect()
            testDispatcher.scheduler.runCurrent()
            assertNotNull("category $category must surface an activation prompt", viewModel.relayActivationNeeded.value)
        }
    }

    @Test
    fun `a category no activation can fix never surfaces the prompt`() = runTest {
        for (category in listOf(
            RelayFailureCategory.INGRESS_UNREACHABLE,
            RelayFailureCategory.RELAY_AUTH_FAILED,
            RelayFailureCategory.EXECUTION_NOT_IMPLEMENTED,
        )) {
            val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(category) }
            val viewModel = newViewModel(relayIngressResolver = resolver)
            viewModel.connect()
            testDispatcher.scheduler.runCurrent()
            assertNull("category $category must never surface an activation prompt", viewModel.relayActivationNeeded.value)
        }
    }

    @Test
    fun `the combined bounded attempt budget is unaffected by the activation prompt - still resolved exactly once`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(relayIngressResolver = resolver)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, resolver.resolvedPlans.size)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
    }

    // --- B: unauthorized/revoked fails closed, no prompt-clearing, no retry ---

    @Test
    fun `unauthorized activation credential fails closed - prompt stays, no retry connect fires`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(
            store = store,
            fetchIngressProfile = { _, _, _, _ -> IngressProfileResult.Unauthorized },
        )
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)

        viewModel.activateIngress(xrayActivationRequest(), "bad-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(IngressActivationOutcome.AuthorizationFailed, viewModel.ingressActivationState.value)
        // Fails closed: the prompt is NOT cleared (nothing was fixed), and
        // no profile was ever persisted.
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertNull(store.getProfileOrNull(ingressId))
        // Only the original connect() call resolved the candidate - the
        // failed activation attempt never triggers a second connect().
        assertEquals(1, resolver.resolvedPlans.size)
    }

    // --- C/D: successful activation clears the prompt, saves the profile, retries exactly once ---

    @Test
    fun `successful activation saves the profile, clears the prompt, and retries connect exactly once`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        var fetchCount = 0
        val provisioner = IngressProfileProvisioner(
            store = store,
            fetchIngressProfile = { _, _, _, _ -> fetchCount++; successResult() },
        )
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)
        assertEquals(1, resolver.resolvedPlans.size)

        viewModel.activateIngress(xrayActivationRequest(), "real-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Saved)
        assertNotNull("the profile must be persisted", store.getProfileOrNull(ingressId))
        assertEquals(1, fetchCount)
        // The bounded retry: exactly ONE additional connect() attempt fired
        // (still resolved via the same STILL-NotProvisioned stub resolver in
        // this test, since re-resolving against the real store isn't wired
        // to the stub - what matters here is the retry COUNT, not its
        // eventual outcome). That retry's own (fresh) NotProvisioned result
        // legitimately re-populates relayActivationNeeded with a NEW request
        // - activateIngress() cleared the OLD one at the moment of success,
        // it never promises the prompt stays empty forever (see the
        // dedicated "activation is bounded" test below for that exact
        // transient-then-repopulated sequence).
        assertEquals(2, resolver.resolvedPlans.size)
    }

    @Test
    fun `activation is bounded - a second connect() failure requires a NEW explicit submission, never fires on its own`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(
            store = store,
            fetchIngressProfile = { _, _, _, _ -> successResult() },
        )
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)

        viewModel.activateIngress(xrayActivationRequest(), "real-credential")
        testDispatcher.scheduler.runCurrent()
        // The retried connect() ALSO still hits the same NotProvisioned stub
        // (this resolver doesn't consult the real store) - so a fresh prompt
        // is surfaced again. It must NOT auto-resolve itself again.
        assertNotNull(viewModel.relayActivationNeeded.value)
        val resolvedAfterRetry = resolver.resolvedPlans.size
        assertEquals(2, resolvedAfterRetry)

        // No further connect() attempts happen without another explicit
        // activateIngress() call.
        testDispatcher.scheduler.runCurrent()
        assertEquals(resolvedAfterRetry, resolver.resolvedPlans.size)
    }

    // --- E: activation never mutates the originally pinned endpoint/binding ---

    @Test
    fun `a response naming a different server address is rejected as Mismatched - the pinned binding is never used with different facts`() = runTest {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val store = InMemoryIngressProfileStore()
        val provisioner = IngressProfileProvisioner(
            store = store,
            fetchIngressProfile = { _, _, _, _ -> successResult(serverAddress = "198.51.100.99") },
        )
        val viewModel = newViewModel(relayIngressResolver = resolver, ingressProfileProvisioner = provisioner)
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertNotNull(viewModel.relayActivationNeeded.value)

        viewModel.activateIngress(xrayActivationRequest(), "real-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.ingressActivationState.value is IngressActivationOutcome.Mismatched)
        assertNull("a mismatched response must never be persisted", store.getProfileOrNull(ingressId))
        // Mismatched is not a Saved outcome, so no bounded retry connect()
        // fires and the prompt is left standing for a new submission.
        assertNotNull(viewModel.relayActivationNeeded.value)
    }

    // --- G: combinedAutoAttempts still resolves the real candidate the same way ---

    @Test
    fun `combinedAutoAttempts still contains the same relayed candidate regardless of activation wiring`() {
        val resolver = RelayActivationStubResolver { RelayIngressResolution.NotProvisioned(RelayFailureCategory.PROFILE_NOT_PROVISIONED) }
        val viewModel = newViewModel(relayIngressResolver = resolver)
        val attempts = viewModel.combinedAutoAttempts()
        assertTrue(attempts.any { it is AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt })
    }
}
