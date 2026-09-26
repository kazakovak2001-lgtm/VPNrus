@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.ProvisioningUiState
import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointManifestRepository
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.FileLastKnownGoodManifestStore
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.Hysteria2Profile
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.reachability.withHysteria2Profile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeHysteria2CredentialRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
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

/**
 * B46-4A review fix (Finding 5) - proves Hysteria2ProfileProvisioner is
 * actually COMPOSED into the normal activation flow (activateDevice), not
 * merely existing as an uncalled class in source. Mirrors the existing
 * targetXrayProvisioner/targetXrayTlsProvisioner coverage's own shape:
 * same activation credential, same device public key, exact endpoint,
 * requires a trusted signed HYSTERIA2 binding before provisioning, a
 * successful save updates HYSTERIA2's own registry availability, a failed
 * provision never does, and none of this blocks the AWG activation itself.
 */
class MainViewModelHysteria2ProvisioningCompositionTest {

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

    private fun germanyMatchingSuccess() = ProvisioningResult.Success(
        clientTunnelIp = "10.77.0.5",
        gatewayPublicKey = ProductionGatewayCatalog.GERMANY.awg.serverPublicKeyBase64,
        gatewayTunnelIp = ProductionGatewayCatalog.GERMANY.awg.gatewayTunnelIp,
        endpointHost = ProductionGatewayCatalog.GERMANY.awg.endpointHost,
        endpointPort = ProductionGatewayCatalog.GERMANY.awg.endpointPort,
    )

    private fun manifestWithHysteria2Binding(vararg endpointIds: EndpointId): EndpointManifestRepository {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = endpointIds.map { id ->
                EndpointDescriptor(
                    id = id,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "test",
                    provider = "test",
                    transports = listOf(
                        EndpointTransportBinding(TransportKind.HYSTERIA2, "203.0.113.10", 443)
                            .withHysteria2Profile(Hysteria2Profile(sni = "hy2.example.com", obfuscationMode = "NONE")),
                    ),
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

    private val successfulHysteria2Fetch: (String, String, String) -> net.pocvpn.client.provisioning.Hysteria2ProfileResult = { _, _, endpointHost ->
        net.pocvpn.client.provisioning.Hysteria2ProfileResult.Success(
            serverAddress = endpointHost,
            serverPort = 443,
            authSecret = "a".repeat(64),
            sni = "hy2.example.com",
            obfuscationMode = "NONE",
            obfuscationSecret = null,
            profileVersion = 1,
            issuedAtEpochSeconds = null,
            expiresAtEpochSeconds = null,
        )
    }

    private fun newViewModel(
        hysteria2CredentialRepositories: Map<EndpointId, net.pocvpn.client.identity.Hysteria2CredentialRepository>,
        manifestRepository: EndpointManifestRepository?,
        activationResult: ProvisioningResult = germanyMatchingSuccess(),
        // Test seam - never a real network call; overridden per test where a
        // non-default (mismatched/failing) fetch outcome is needed.
        hysteria2Fetch: (String, String, String) -> net.pocvpn.client.provisioning.Hysteria2ProfileResult = successfulHysteria2Fetch,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(publicKey = "device-public-key"),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        hysteria2Transport = FakeVpnTransport(kind = TransportKind.HYSTERIA2),
        hysteria2CredentialRepositories = hysteria2CredentialRepositories,
        hysteria2BinaryEligibility = net.pocvpn.client.vpn.hysteria.Hysteria2BinaryEligibility.Eligible,
        hysteria2ProfileProvisionerFactory = { repository ->
            net.pocvpn.client.provisioning.Hysteria2ProfileProvisioner(repository, hysteria2Fetch)
        },
        manifestRepository = manifestRepository,
        activationClient = { _, _, _ -> activationResult },
        stockholmActivationClient = { _, _, _ -> activationResult },
        ioDispatcher = testDispatcher,
    )

    @Test
    fun `successful AWG activation with a wired repository and trusted binding provisions and saves the Hysteria2 credential`() = runTest {
        val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(germanyId to FakeHysteria2CredentialRepository()),
            manifestRepository = manifestWithHysteria2Binding(germanyId),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals(
            net.pocvpn.client.provisioning.Hysteria2ProvisioningOutcome.Saved,
            viewModel.hysteria2ProfileProvisioningState.value,
        )
        // The real observable effect: the registry now reports HYSTERIA2 AVAILABLE for this endpoint.
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germanyId).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `no trusted signed HYSTERIA2 binding - provisioning is skipped entirely, AWG activation still succeeds`() = runTest {
        val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(germanyId to FakeHysteria2CredentialRepository()),
            manifestRepository = null, // no manifest at all -> no trusted binding
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue("AWG activation must succeed regardless of Hysteria2 provisioning", viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertNull("provisioning must never even attempt without a trusted binding", viewModel.hysteria2ProfileProvisioningState.value)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyId).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `failed provisioning never blocks AWG activation and never makes HYSTERIA2 available`() = runTest {
        val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(germanyId to FakeHysteria2CredentialRepository()),
            manifestRepository = manifestWithHysteria2Binding(germanyId),
            hysteria2Fetch = { _, _, _ -> net.pocvpn.client.provisioning.Hysteria2ProfileResult.Unauthorized },
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue("AWG activation must still succeed", viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertEquals(
            net.pocvpn.client.provisioning.Hysteria2ProvisioningOutcome.AuthorizationFailed,
            viewModel.hysteria2ProfileProvisioningState.value,
        )
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(germanyId).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `no credential repository wired for the endpoint - provisioning is skipped entirely`() = runTest {
        val germanyId = ProductionGatewayCatalog.GERMANY.endpointId
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = emptyMap(),
            manifestRepository = manifestWithHysteria2Binding(germanyId),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.provisioningState.value is ProvisioningUiState.Success)
        assertNull(viewModel.hysteria2ProfileProvisioningState.value)
    }
}
