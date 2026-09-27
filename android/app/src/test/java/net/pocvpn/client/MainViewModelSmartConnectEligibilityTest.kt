@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.activation.ActivationPackageFixtures
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
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
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeClientTunnelIdentityStore
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeSelectedGatewayStore
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.config.ProductionGatewayId
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

/**
 * B67.7 - proves the real Smart Connect integration boundary: a genuinely
 * SUCCESSFUL, entitlement-scoped activation narrows
 * [MainViewModel.autoGatewayCandidates]/[MainViewModel.combinedAutoAttempts]
 * (the SAME lists [MainViewModel.connectAuto] uses) to the B67.6 eligible
 * gateway set, a PLURAL eligible set reaches both lists intact, and a
 * server-rejected attempt never narrows anything - `AutoGatewaySelector`/
 * `TransportOrchestrator` themselves are never touched or reimplemented.
 */
class MainViewModelSmartConnectEligibilityTest {

    private val testDispatcher = StandardTestDispatcher()

    @get:Rule val tmp = TemporaryFolder()
    private lateinit var fixtures: ActivationPackageFixtures
    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("test-manifest-key") to manifestSigningKey.generatePublicKey().encoded),
    )
    private val bothProvisioned = FakeClientTunnelIdentityStore(
        mapOf(ProductionGatewayId.GERMANY to "10.77.0.5", ProductionGatewayId.STOCKHOLM to "10.77.0.2"),
    )

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
        fixtures = ActivationPackageFixtures(tmp.newFolder())
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

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

    private fun successFor(gatewayId: ProductionGatewayId): ProvisioningResult.Success {
        val gateway = ProductionGatewayCatalog.byId(gatewayId)
        return ProvisioningResult.Success(
            clientTunnelIp = "10.77.0.9",
            gatewayPublicKey = gateway.awg.serverPublicKeyBase64,
            gatewayTunnelIp = gateway.awg.gatewayTunnelIp,
            endpointHost = gateway.awg.endpointHost,
            endpointPort = gateway.awg.endpointPort,
        )
    }

    private fun newViewModel(
        germanyResult: ProvisioningResult,
        stockholmResult: ProvisioningResult,
        manifestRepository: EndpointManifestRepository = manifestRepositoryNaming("frankfurt", "stockholm"),
    ): MainViewModel = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = bothProvisioned,
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, _, _ -> germanyResult },
        stockholmActivationClient = { _, _, _ -> stockholmResult },
        nowProvider = { fixtures.now },
        activationPackageImporter = fixtures.importer(),
        manifestRepository = manifestRepository,
        ioDispatcher = testDispatcher,
    )

    @Test
    fun `before any package is redeemed, Smart Connect candidates are unrestricted - restart-equivalent baseline`() {
        val viewModel = newViewModel(successFor(ProductionGatewayId.GERMANY), successFor(ProductionGatewayId.STOCKHOLM))
        assertEquals(
            setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            viewModel.autoGatewayCandidates().map { it.gatewayId }.toSet(),
        )
    }

    @Test
    fun `a successful single-eligible-gateway redemption narrows both autoGatewayCandidates and combinedAutoAttempts, even though the other gateway is also provisioned and trusted`() = runTest {
        val viewModel = newViewModel(successFor(ProductionGatewayId.GERMANY), successFor(ProductionGatewayId.STOCKHOLM))
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("stockholm"))))
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(listOf(ProductionGatewayId.STOCKHOLM), viewModel.autoGatewayCandidates().map { it.gatewayId })
        assertTrue(
            viewModel.combinedAutoAttempts().all {
                it is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.DirectAttempt &&
                    it.candidate.gatewayId == ProductionGatewayId.STOCKHOLM ||
                    it !is net.pocvpn.client.smartconnect.AutoGatewaySelector.AutoConnectAttempt.DirectAttempt
            },
        )
    }

    @Test
    fun `a successful multi-eligible-gateway redemption preserves BOTH gateways as Smart Connect candidates - plural set reaches AutoGatewaySelector`() = runTest {
        val viewModel = newViewModel(successFor(ProductionGatewayId.GERMANY), successFor(ProductionGatewayId.STOCKHOLM))
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("frankfurt"), EndpointId("stockholm"))))
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(
            setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            viewModel.autoGatewayCandidates().map { it.gatewayId }.toSet(),
        )
    }

    @Test
    fun `a server-rejected (revoked) hinted activation never narrows Smart Connect - no entitlement was actually proven`() = runTest {
        // Stockholm's OWN activation store rejects this credential (revoked)
        // even though the envelope's signed hint named it and the trusted
        // manifest/catalog both recognize it - eligibility resolution alone
        // must never be mistaken for proven entitlement.
        val viewModel = newViewModel(successFor(ProductionGatewayId.GERMANY), ProvisioningResult.Revoked)
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("stockholm"))))
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        // Activation itself failed closed (existing B67.3/B30 behavior, unchanged)...
        assertTrue(viewModel.provisioningState.value is net.pocvpn.client.provisioning.ProvisioningUiState.Revoked)
        // ...and Smart Connect stays completely unrestricted - both gateways
        // this device is genuinely already provisioned for remain candidates.
        assertEquals(
            setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            viewModel.autoGatewayCandidates().map { it.gatewayId }.toSet(),
        )
    }

    @Test
    fun `an unscoped (legacy-shaped) successful redemption never narrows Smart Connect to whatever gateway it explicitly targeted`() = runTest {
        val viewModel = newViewModel(successFor(ProductionGatewayId.GERMANY), successFor(ProductionGatewayId.STOCKHOLM))
        testDispatcher.scheduler.runCurrent()

        // No hints at all - EntitlementScope.Unscoped.
        viewModel.importActivationPackage(fixtures.packageText(), targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        assertTrue(viewModel.provisioningState.value is net.pocvpn.client.provisioning.ProvisioningUiState.Success)
        assertEquals(
            setOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM),
            viewModel.autoGatewayCandidates().map { it.gatewayId }.toSet(),
        )
    }

    @Test
    fun `a manifest that no longer trusts an eligible gateway still excludes it - manifest trust remains authoritative over the eligibility constraint`() = runTest {
        // Only Frankfurt is trusted here, even though this device is
        // "eligible" (and provisioned) for both.
        val viewModel = newViewModel(
            successFor(ProductionGatewayId.GERMANY),
            successFor(ProductionGatewayId.STOCKHOLM),
            manifestRepository = manifestRepositoryNaming("frankfurt"),
        )
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("frankfurt"), EndpointId("stockholm"))))
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        // Eligibility only ever NARROWS an already-trusted list - Stockholm
        // was never a candidate in the first place (not in the trusted
        // manifest), regardless of what the envelope hinted.
        assertEquals(listOf(ProductionGatewayId.GERMANY), viewModel.autoGatewayCandidates().map { it.gatewayId })
    }
}
