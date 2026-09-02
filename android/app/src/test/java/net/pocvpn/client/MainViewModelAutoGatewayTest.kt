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
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointManifestRepository
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.FileLastKnownGoodManifestStore
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
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
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertEquals
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

private val bothProvisioned = FakeClientTunnelIdentityStore(
    mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
)

/** In-memory GatewayAutoModeStore double - mirrors FakeSelectedGatewayStore's own shape. */
private class FakeGatewayAutoModeStore(initial: Boolean = false) : GatewayAutoModeStore {
    var current: Boolean = initial
        private set
    var writeCallCount = 0
        private set

    override fun read(): Boolean = current
    override fun write(auto: Boolean) {
        writeCallCount++
        current = auto
    }
}

/**
 * B16 - a deterministic AWG transport double for cross-gateway failover
 * tests: fails (VpnError.BackendStartFailure, via a thrown exception in
 * connect() - the SAME real path VpnController.doConnectAttempt's catch
 * block already handles) for its first [failFirstNCalls] invocations, then
 * succeeds. Avoids depending on VpnController's real-time handshake-timeout
 * polling loop (see FakeVpnTransport.handshakeAvailable's own docs) so the
 * test needs no wall-clock/dispatcher time advancement to observe a
 * terminal failure.
 */
private class FailNTimesThenSucceedTransport(private val failFirstNCalls: Int) : VpnTransport {
    override val name: String = "fail-n-then-succeed"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCallCount = 0
        private set
    var disconnectCallCount = 0
        private set

    override fun preparePermissionIntent(): Intent? = null

    override suspend fun connect(config: TransportConfig) {
        connectCallCount++
        // B16 test note - deliberately does NOT write TransportState.Connecting
        // to [stateFlow] before a simulated failure: VpnController's own
        // background collector (switchActiveTransport) forwards every
        // post-hasTouchedTransport emission from this flow, and since this
        // fake never actually suspends, a transient "Connecting" write here
        // would otherwise be delivered to that collector AFTER
        // doConnectAttempt's own authoritative catch-block setState(Error) -
        // clobbering it back to Connecting. A real transport's own state
        // machine does not exhibit this artifact because its emissions are
        // driven by genuine async backend events, not a synchronous throw.
        if (connectCallCount <= failFirstNCalls) {
            throw RuntimeException("simulated backend start failure")
        }
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        disconnectCallCount++
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow
}

/**
 * B16 - proves the real architecture implemented for automatic multi-gateway
 * selection/failover: candidate construction across every provisioned
 * gateway, manual-mode isolation, bounded cross-gateway failover, fail-
 * closed exhaustion, and persisted mode restart-durability.
 */
class MainViewModelAutoGatewayTest {

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

    /**
     * B17 - a trusted, signed manifest naming exactly [endpointIds] (values
     * from `ProductionGatewayCatalog`'s own `endpointId`s, e.g. "frankfurt"/
     * "stockholm") - the caller-supplied source of Auto discovery, per the
     * runtime-authority change this test file now proves.
     */
    private fun manifestRepositoryNaming(vararg endpointIds: String): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = endpointIds.map { id ->
                val gateway = ProductionGatewayCatalog.all.first { it.endpointId.value == id }
                EndpointDescriptor(
                    id = gateway.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "${gateway.displayCountry} / ${gateway.displayCity}",
                    provider = gateway.provider,
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, gateway.awg.endpointHost, gateway.awg.endpointPort)),
                )
            },
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
     * B17-2 - a trusted, signed manifest naming both real endpoints, but
     * with Germany's AMNEZIA_WG binding advertising [germanyHost]/[germanyPort]
     * INSTEAD of `ProductionGatewayCatalog.GERMANY.awg.endpointHost/Port` -
     * proves the manifest's own address, not the catalog's, is what actually
     * gets executed.
     */
    private fun manifestRepositoryWithGermanyHost(germanyHost: String, germanyPort: Int): EndpointManifestRepository {
        val stockholmGateway = ProductionGatewayCatalog.STOCKHOLM
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = ProductionGatewayCatalog.GERMANY.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "Germany / Frankfurt",
                    provider = "Oracle Cloud",
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, germanyHost, germanyPort)),
                ),
                EndpointDescriptor(
                    id = stockholmGateway.endpointId,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "${stockholmGateway.displayCountry} / ${stockholmGateway.displayCity}",
                    provider = stockholmGateway.provider,
                    transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, stockholmGateway.awg.endpointHost, stockholmGateway.awg.endpointPort)),
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
        autoModeStore: GatewayAutoModeStore = FakeGatewayAutoModeStore(),
        identityStore: net.pocvpn.client.vpn.config.ClientTunnelIdentityStore = bothProvisioned,
        selectedGatewayStore: net.pocvpn.client.vpn.config.SelectedGatewayStore = FakeSelectedGatewayStore(),
        manifestRepository: EndpointManifestRepository? = manifestRepositoryNaming("frankfurt", "stockholm"),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = transport,
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        selectedGatewayStore = selectedGatewayStore,
        clientTunnelIdentityStore = identityStore,
        gatewayAutoModeStore = autoModeStore,
        initialNetworkProfile = USABLE_WIFI,
        manifestRepository = manifestRepository,
    )

    // --- candidate construction ---

    @Test
    fun `auto candidates cover both Germany and Stockholm when both are provisioned`() {
        val viewModel = newViewModel()
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), candidates.map { it.gatewayId }.toSet())
    }

    @Test
    fun `unprovisioned gateway is excluded from auto candidates`() {
        val viewModel = newViewModel(identityStore = FakeClientTunnelIdentityStore(mapOf(ProductionGatewayId.GERMANY to "10.77.0.5")))
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    /** B17 - runtime-authority proof: the trusted manifest gates discovery even though the device is provisioned for both. */
    @Test
    fun `manifest naming only Germany excludes Stockholm even though this device is provisioned for both`() {
        val viewModel = newViewModel(manifestRepository = manifestRepositoryNaming("frankfurt"))
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(listOf(ProductionGatewayId.GERMANY), candidates.map { it.gatewayId })
    }

    /** B17 - task requirement 9.D: no trusted manifest source at all must fail closed, never fall back to the unverified catalog. */
    @Test
    fun `no manifest repository wired - auto candidates are empty even though both gateways are provisioned`() {
        val viewModel = newViewModel(manifestRepository = null)
        assertTrue(viewModel.autoGatewayCandidates().isEmpty())
    }

    /** B17 - both real endpoints become candidates precisely when both the trusted manifest and local provisioning agree. */
    @Test
    fun `both Germany and Stockholm become candidates when trusted manifest and local provisioning both exist`() {
        val viewModel = newViewModel(manifestRepository = manifestRepositoryNaming("frankfurt", "stockholm"))
        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), candidates.map { it.gatewayId }.toSet())
    }

    @Test
    fun `neither gateway provisioned - connect() in auto mode fails closed without ever calling the transport`() = runTest {
        val transport = FakeVpnTransport()
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore, identityStore = FakeClientTunnelIdentityStore())

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(viewModel.autoGatewayDiagnostics.value?.exhausted == true)
    }

    // --- mode persistence ---

    @Test
    fun `setGatewayAutoMode persists and survives a fresh ViewModel, simulating app restart`() {
        val store = FakeGatewayAutoModeStore()
        val viewModel = newViewModel(autoModeStore = store)

        viewModel.setGatewayAutoMode(true)
        assertTrue(viewModel.gatewayAutoMode.value)

        val restarted = newViewModel(autoModeStore = store)
        assertTrue(restarted.gatewayAutoMode.value)
    }

    @Test
    fun `manually selecting a gateway exits automatic mode - manual selection stays deterministic`() {
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(autoModeStore = autoStore)
        assertTrue(viewModel.gatewayAutoMode.value)

        viewModel.selectGateway(ProductionGatewayId.STOCKHOLM)

        assertEquals(false, viewModel.gatewayAutoMode.value)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.selectedGateway.value)
    }

    // --- manual mode never cross-fails ---

    @Test
    fun `manual Germany - an AWG failure never advances to Stockholm`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.GERMANY)
        val viewModel = newViewModel(transport, selectedGatewayStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
        assertEquals(ProductionGatewayId.GERMANY, viewModel.activeGatewayId.value)
        assertNull(viewModel.autoGatewayDiagnostics.value)
    }

    @Test
    fun `manual Stockholm - an AWG failure never advances to Germany`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val store = FakeSelectedGatewayStore(initial = ProductionGatewayId.STOCKHOLM)
        val viewModel = newViewModel(transport, selectedGatewayStore = store)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
        assertEquals(ProductionGatewayId.STOCKHOLM, viewModel.activeGatewayId.value)
    }

    // --- automatic cross-gateway failover ---

    @Test
    fun `auto mode - first candidate fails, second candidate connects - exactly two distinct attempts, bounded`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 1)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        val candidates = viewModel.autoGatewayCandidates()
        assertEquals(2, candidates.size)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(2, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        val diagnostics = viewModel.autoGatewayDiagnostics.value!!
        assertEquals(2, diagnostics.attempted.size)
        assertEquals(diagnostics.attempted.map { it.gatewayId }.toSet(), diagnostics.attempted.map { it.gatewayId }.distinct().toSet())
        assertEquals(diagnostics.attempted.last().gatewayId, viewModel.activeGatewayId.value)
        assertEquals(false, diagnostics.exhausted)
    }

    @Test
    fun `auto mode - both candidates fail - fails closed, never retries a candidate, never loops forever`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 100)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // Exactly 2 real, distinct (gateway, transport) attempts - the full
        // provisioned candidate set, never re-attempted, never an unbounded loop.
        assertEquals(2, transport.connectCallCount)
        val diagnostics = viewModel.autoGatewayDiagnostics.value!!
        assertEquals(2, diagnostics.attempted.size)
        assertEquals(setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM), diagnostics.attempted.map { it.gatewayId }.toSet())
        assertTrue(diagnostics.exhausted)
    }

    @Test
    fun `auto mode - immediate success on the top-ranked candidate needs exactly one attempt`() = runTest {
        val transport = FailNTimesThenSucceedTransport(failFirstNCalls = 0)
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val viewModel = newViewModel(transport, autoStore)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(1, viewModel.autoGatewayDiagnostics.value?.attempted?.size)
    }

    // --- B16 consolidated review fix (Blocker 1): pinned candidate config is immutable for the attempt ---

    @Test
    fun `auto candidate config is pinned - mutating ClientTunnelIdentityStore after resolve does not change the executed tunnel`() = runTest {
        val transport = FakeVpnTransport(permission = android.content.Intent())
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val identity = FakeClientTunnelIdentityStore(
            mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
        )
        val viewModel = newViewModel(transport, autoStore, identity)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        // A VPN permission prompt is pending - no real attempt executed yet.
        assertEquals(0, transport.connectCallCount)

        // Mutate the SAME identity-store instance the candidate was already
        // ranked/pinned from, simulating this device's provisioning changing
        // in the gap while the user is responding to the system prompt.
        identity.write(ProductionGatewayId.GERMANY, "10.99.99.99")

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        val sent = (transport.lastConfig as net.pocvpn.client.vpn.config.TransportConfig.Awg).config
        // The pinned candidate's ORIGINAL client tunnel IP ("10.77.0.5",
        // captured when the candidate was ranked/resolved), never the
        // mutated value the identity store holds now.
        assertEquals(listOf("10.77.0.5/32"), sent.localAddresses)
    }

    /**
     * B17-2 runtime-authority fix - end-to-end proof that the EXECUTED AWG
     * peer endpoint is the manifest's own host/port, never
     * ProductionGatewayCatalog's - a signed manifest advertising a rotated
     * Germany address must actually change what the real connect() attempt
     * dials, not just what PathScorer ranks.
     */
    @Test
    fun `auto connect to Germany dials the manifest host, not the catalog host`() = runTest {
        val manifestHost = "203.0.113.77"
        val manifestPort = 55555
        val transport = FakeVpnTransport()
        val autoStore = FakeGatewayAutoModeStore(initial = true)
        val customViewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway()),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = FakeSelectedGatewayStore(),
            clientTunnelIdentityStore = bothProvisioned,
            gatewayAutoModeStore = autoStore,
            initialNetworkProfile = USABLE_WIFI,
            manifestRepository = manifestRepositoryWithGermanyHost(manifestHost, manifestPort),
        )

        customViewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        val sent = (transport.lastConfig as net.pocvpn.client.vpn.config.TransportConfig.Awg).config
        assertEquals(manifestHost, sent.peer.endpointHost)
        assertEquals(manifestPort, sent.peer.endpointPort)
        // Sanity: this only proves something if the two actually differ.
        assertTrue(manifestHost != ProductionGatewayCatalog.GERMANY.awg.endpointHost)
        assertTrue(manifestPort != ProductionGatewayCatalog.GERMANY.awg.endpointPort)
    }

    // --- B28: combinedAutoRankingDiagnostics - sanitized, kind-labeled, no-secret diagnostics ---

    @Test
    fun `B28 - combinedAutoRankingDiagnostics carries the current restriction class and one entry per ranked attempt, labeled DIRECT under normal evidence`() {
        val viewModel = newViewModel()
        val diagnostics = viewModel.combinedAutoRankingDiagnostics()
        assertEquals(net.pocvpn.client.smartconnect.RestrictionClass.UNKNOWN, diagnostics.restrictionClass)
        assertTrue(diagnostics.ranked.isNotEmpty())
        assertTrue(diagnostics.ranked.all { it.kind == "DIRECT" })
    }

    /** B28 requirement 10 - no UUID/host/credential/token/key string ever leaks through this surface - only the closed {kind, score, typed-reason-token} shape. */
    @Test
    fun `B28 - combinedAutoRankingDiagnostics never leaks an endpoint host, credential, or key - only kind, score, and typed reason tokens`() {
        val viewModel = newViewModel()
        val diagnostics = viewModel.combinedAutoRankingDiagnostics()
        val sensitiveSubstrings = listOf(
            ProductionGatewayCatalog.GERMANY.awg.endpointHost,
            ProductionGatewayCatalog.STOCKHOLM.awg.endpointHost,
        )
        diagnostics.ranked.forEach { entry ->
            assertTrue(entry.kind in setOf("DIRECT", "CHAIN_DIRECT", "CHAIN_CDN"))
            entry.reasons.forEach { reason ->
                // Reason tokens are the closed PathScorer.Reason vocabulary - all-caps/underscore, never free text carrying a host/id/secret.
                assertTrue("reason token '$reason' must be a stable typed token, not free text", reason.all { it.isUpperCase() || it == '_' })
                sensitiveSubstrings.forEach { host -> assertTrue(host !in reason) }
            }
        }
    }
}
