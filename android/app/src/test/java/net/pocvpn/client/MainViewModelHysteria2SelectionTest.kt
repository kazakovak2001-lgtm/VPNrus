@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.Hysteria2CredentialValidator
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
import net.pocvpn.client.vpn.hysteria.Hysteria2BinaryEligibility
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

/**
 * B46-4A review fix (Finding 4) - mirrors [MainViewModelShadowsocksSelectionTest]'s
 * own shape exactly for HYSTERIA2: proves registry eligibility genuinely
 * requires all four narrow facts (ABI+binary eligibility, a wired
 * per-endpoint credential source, a validated credential for THAT endpoint,
 * a trusted signed HYSTERIA2 binding) and stays NOT_IMPLEMENTED/fail-closed
 * whenever any one is missing - never a fake AVAILABLE state. This is the
 * closest a JVM unit test can get to proving the production
 * `MainViewModel.Factory` wiring is correct: `Factory.create()` itself
 * cannot be exercised end to end in this test environment because
 * `Hysteria2CredentialRepositoryFactory.create`'s eager `AndroidKeystoreAesGcmEncryptor`
 * construction hits a real `KeyStoreException` under Robolectric - the SAME
 * PRE-EXISTING constraint `RelayCompositionFactoryTest`'s own doc already
 * documents for `xrayProfileRepository`/`clientKeyRepository`, unrelated to
 * and not introduced by this slice. The Factory's own wiring (passing real,
 * non-null `hysteria2Transport`/`hysteria2CredentialRepositories`/
 * `hysteria2BinaryEligibility` values, and the SAME transport instance into
 * both the registry and `VpnController`) is verified by direct code
 * inspection - see `MainViewModel.Factory.create`'s own HYSTERIA2 block.
 */
class MainViewModelHysteria2SelectionTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val endpointA = EndpointId("endpoint-a")
    private val endpointB = EndpointId("endpoint-b")
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

    private fun validCredential(endpointId: EndpointId) =
        (
            Hysteria2CredentialValidator.validate(endpointId, "a".repeat(64), null)
                as net.pocvpn.client.identity.Hysteria2CredentialValidationResult.Valid
            ).credential

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

    private fun newViewModel(
        hysteria2Transport: FakeVpnTransport? = FakeVpnTransport(kind = TransportKind.HYSTERIA2),
        hysteria2CredentialRepositories: Map<EndpointId, net.pocvpn.client.identity.Hysteria2CredentialRepository> =
            mapOf(endpointA to FakeHysteria2CredentialRepository(validCredential(endpointA))),
        hysteria2BinaryEligibility: Hysteria2BinaryEligibility = Hysteria2BinaryEligibility.Eligible,
        manifestRepository: EndpointManifestRepository? = manifestWithHysteria2Binding(endpointA),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        hysteria2Transport = hysteria2Transport,
        hysteria2CredentialRepositories = hysteria2CredentialRepositories,
        hysteria2BinaryEligibility = hysteria2BinaryEligibility,
        manifestRepository = manifestRepository,
    )

    @Test
    fun `valid credential plus eligible ABI-binary plus trusted binding - HYSTERIA2 becomes AVAILABLE with the real registered instance`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.HYSTERIA2)
        val viewModel = newViewModel(hysteria2Transport = transport)
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.AVAILABLE, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
        // The registered factory produces the EXACT SAME instance this
        // ViewModel was given - never a second/independently-constructed one.
        assertEquals(transport, registry.createTransport(TransportKind.HYSTERIA2))
    }

    @Test
    fun `unsupported ABI - HYSTERIA2 stays NOT_IMPLEMENTED even with a valid credential and trusted binding`() = runTest {
        val viewModel = newViewModel(
            hysteria2BinaryEligibility = Hysteria2BinaryEligibility.UnsupportedAbi(listOf("armeabi-v7a")),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
        assertNull(registry.createTransport(TransportKind.HYSTERIA2))
    }

    @Test
    fun `binary unavailable - HYSTERIA2 stays NOT_IMPLEMENTED even with a valid credential and trusted binding`() = runTest {
        val viewModel = newViewModel(
            hysteria2BinaryEligibility = Hysteria2BinaryEligibility.BinaryUnavailable("not packaged"),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
        assertNull(registry.createTransport(TransportKind.HYSTERIA2))
    }

    @Test
    fun `missing credential - HYSTERIA2 stays NOT_IMPLEMENTED even with an eligible ABI-binary and trusted binding`() = runTest {
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(endpointA to FakeHysteria2CredentialRepository(credential = null)),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `corrupted credential - HYSTERIA2 stays NOT_IMPLEMENTED, never trusted just because a file exists`() = runTest {
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(endpointA to FakeHysteria2CredentialRepository(corrupted = true)),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `no manifest binding at all - a locally persisted credential alone never authorizes the endpoint`() = runTest {
        val viewModel = newViewModel(manifestRepository = null)
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `no credential repository wired for any endpoint - stays NOT_IMPLEMENTED, no fabricated availability`() = runTest {
        val viewModel = newViewModel(hysteria2CredentialRepositories = emptyMap())
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `no Hysteria2Transport wired - descriptor absent entirely, same shape as every other unwired kind`() = runTest {
        val viewModel = newViewModel(hysteria2Transport = null)
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertNull(registry.descriptorFor(TransportKind.HYSTERIA2))
    }

    // --- Endpoint-scoping/isolation ---

    @Test
    fun `endpoint B has no wired repository at all - B stays ineligible`() = runTest {
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(endpointA to FakeHysteria2CredentialRepository(validCredential(endpointA))),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointB).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `multiple endpoints independently resolve their own credentials and bindings - both become eligible`() = runTest {
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(
                endpointA to FakeHysteria2CredentialRepository(validCredential(endpointA)),
                endpointB to FakeHysteria2CredentialRepository(validCredential(endpointB)),
            ),
            manifestRepository = manifestWithHysteria2Binding(endpointA, endpointB),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.HYSTERIA2)?.status)
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointB).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }

    @Test
    fun `Factory wiring is catalog-driven, not country-literal - proves both real catalog gateways are independently representable`() = runTest {
        val germany = ProductionGatewayCatalog.GERMANY.endpointId
        val stockholm = ProductionGatewayCatalog.STOCKHOLM.endpointId
        val viewModel = newViewModel(
            hysteria2CredentialRepositories = mapOf(
                germany to FakeHysteria2CredentialRepository(validCredential(germany)),
                stockholm to FakeHysteria2CredentialRepository(credential = null),
            ),
            manifestRepository = manifestWithHysteria2Binding(germany, stockholm),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germany).descriptorFor(TransportKind.HYSTERIA2)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholm).descriptorFor(TransportKind.HYSTERIA2)?.status)
    }
}
