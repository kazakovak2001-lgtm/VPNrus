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
import net.pocvpn.client.relay.NotConfiguredRelayEndToEndProbe
import net.pocvpn.client.relay.NotProvisionedRelayIngressResolver
import net.pocvpn.client.smartconnect.AutoGatewaySelector
import net.pocvpn.client.smartconnect.ProductionIngressEndpoints
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
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
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
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
        relayIngressResolver = NotProvisionedRelayIngressResolver,
        relayEndToEndProbe = NotConfiguredRelayEndToEndProbe,
    )

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
}
