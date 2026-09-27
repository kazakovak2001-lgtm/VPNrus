@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.activation.ActivationPackageFixtures
import net.pocvpn.client.activation.ActivationPackageRejectionKind
import net.pocvpn.client.activation.ActivationPackageUiState
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
 * B67.6 - proves the real `MainViewModel.importActivationPackage` wiring of
 * [net.pocvpn.client.activation.EntitlementGatewayEligibility]: a signed
 * hint that resolves to a DIFFERENT gateway than the caller's own explicit/
 * UI-selected target is honored (never silently overridden by whatever was
 * merely selected in the picker); a hint the trusted manifest does not
 * currently back fails closed before any network call; and an unhinted
 * (legacy-shaped) envelope is completely unaffected (today's exact
 * behavior, `EntitlementScope.Unscoped`).
 */
class MainViewModelEntitlementGatewayEligibilityTest {

    private val testDispatcher = StandardTestDispatcher()

    @get:Rule val tmp = TemporaryFolder()
    private lateinit var fixtures: ActivationPackageFixtures
    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("test-manifest-key") to manifestSigningKey.generatePublicKey().encoded),
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

    private fun newViewModel(
        manifestRepository: EndpointManifestRepository?,
        germanyCalls: MutableList<String> = mutableListOf(),
        stockholmCalls: MutableList<String> = mutableListOf(),
    ): MainViewModel = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        clientTunnelIdentityStore = FakeClientTunnelIdentityStore(),
        selectedGatewayStore = FakeSelectedGatewayStore(),
        activationClient = { _, _, cred -> germanyCalls += cred; ProvisioningResult.Revoked },
        stockholmActivationClient = { _, _, cred -> stockholmCalls += cred; ProvisioningResult.Revoked },
        nowProvider = { fixtures.now },
        activationPackageImporter = fixtures.importer(),
        manifestRepository = manifestRepository,
        ioDispatcher = testDispatcher,
    )

    @Test
    fun `an envelope hinting a DIFFERENT trusted, catalog-known gateway than the UI selection activates against the hinted one`() = runTest {
        val germanyCalls = mutableListOf<String>()
        val stockholmCalls = mutableListOf<String>()
        val viewModel = newViewModel(
            manifestRepository = manifestRepositoryNaming("frankfurt", "stockholm"),
            germanyCalls = germanyCalls,
            stockholmCalls = stockholmCalls,
        )
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("stockholm"))))
        // targetGatewayId defaults to selectedGateway.value, i.e. Germany - deliberately NOT the hint.
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(listOf(fixtures.credential), stockholmCalls)
        assertTrue(germanyCalls.isEmpty())
    }

    @Test
    fun `an envelope hinting an endpoint the trusted manifest does not carry fails closed - no network attempt on either gateway`() = runTest {
        val germanyCalls = mutableListOf<String>()
        val stockholmCalls = mutableListOf<String>()
        val viewModel = newViewModel(
            manifestRepository = manifestRepositoryNaming("frankfurt"), // Stockholm is NOT trusted here
            germanyCalls = germanyCalls,
            stockholmCalls = stockholmCalls,
        )
        testDispatcher.scheduler.runCurrent()

        val text = fixtures.packageText(fixtures.envelope(hints = listOf(EndpointId("stockholm"))))
        viewModel.importActivationPackage(text, targetGatewayId = ProductionGatewayId.GERMANY)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(
            ActivationPackageUiState.Rejected(ActivationPackageRejectionKind.GATEWAY_NOT_ELIGIBLE),
            viewModel.activationPackageState.value,
        )
        assertTrue(germanyCalls.isEmpty())
        assertTrue(stockholmCalls.isEmpty())
    }

    @Test
    fun `an envelope with no hints at all is unaffected - activates against the explicit UI-selected gateway exactly as before`() = runTest {
        val germanyCalls = mutableListOf<String>()
        val stockholmCalls = mutableListOf<String>()
        // No trusted manifest wired at all - EntitlementScope.Unscoped must never consult it.
        val viewModel = newViewModel(manifestRepository = null, germanyCalls = germanyCalls, stockholmCalls = stockholmCalls)
        testDispatcher.scheduler.runCurrent()

        viewModel.importActivationPackage(fixtures.packageText(), targetGatewayId = ProductionGatewayId.STOCKHOLM)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(listOf(fixtures.credential), stockholmCalls)
        assertTrue(germanyCalls.isEmpty())
    }
}
