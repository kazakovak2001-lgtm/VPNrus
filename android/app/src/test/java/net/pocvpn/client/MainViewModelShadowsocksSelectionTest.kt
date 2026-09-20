@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.Shadowsocks2022CredentialValidator
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
import net.pocvpn.client.reachability.Shadowsocks2022Profile
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import net.pocvpn.client.reachability.withShadowsocks2022Profile
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeShadowsocks2022CredentialRepository
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import net.pocvpn.client.vpn.shadowsocks.ShadowsocksBinaryEligibility
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
import java.util.Base64

private val VALID_KEY_BASE64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
private const val TEST_SS_METHOD = "2022-blake3-aes-256-gcm"

/**
 * B45B-4 (review fix) - proves SHADOWSOCKS_2022's registry eligibility
 * genuinely requires all three narrow facts (ABI+binary eligibility, a
 * wired per-endpoint credential source, a validated credential for THAT
 * endpoint) and stays NOT_IMPLEMENTED/fail-closed whenever any one is
 * missing - never a fake AVAILABLE state, and never a country/provider
 * literal deciding availability. [shadowsocksCredentialRepositories] is a
 * plain `Map<EndpointId, Shadowsocks2022CredentialRepository>` (the same
 * shape [MainViewModel]'s Factory populates from `ProductionGatewayCatalog.all`,
 * never a single Germany-fixed field) - these tests exercise it with
 * arbitrary, non-catalog endpoint ids to prove nothing here depends on a
 * specific country/provider name.
 */
class MainViewModelShadowsocksSelectionTest {

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
            Shadowsocks2022CredentialValidator.validate(endpointId, TEST_SS_METHOD, VALID_KEY_BASE64)
                as net.pocvpn.client.identity.Shadowsocks2022CredentialValidationResult.Valid
            ).credential

    /**
     * B45B-4P (correction) - a trusted, signed manifest naming a real, typed
     * SHADOWSOCKS_2022 binding for exactly [endpointIds] - the manifest half
     * of the now-mandatory "a device-local secret alone never authorizes an
     * endpoint" eligibility check (see MainViewModel.isShadowsocksAvailableFor's
     * own docs). Defaults to naming only [endpointA] so every pre-existing
     * test in this file (whose intent is exercising the CREDENTIAL side of
     * eligibility) keeps its original meaning once wired.
     */
    private fun manifestWithShadowsocksBinding(vararg endpointIds: EndpointId): EndpointManifestRepository {
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
                        EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "152.70.43.1", 28388)
                            .withShadowsocks2022Profile(Shadowsocks2022Profile(TEST_SS_METHOD)),
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
        shadowsocksTransport: FakeVpnTransport? = FakeVpnTransport(kind = TransportKind.SHADOWSOCKS_2022),
        shadowsocksCredentialRepositories: Map<EndpointId, net.pocvpn.client.identity.Shadowsocks2022CredentialRepository> =
            mapOf(endpointA to FakeShadowsocks2022CredentialRepository(validCredential(endpointA))),
        shadowsocksBinaryEligibility: ShadowsocksBinaryEligibility = ShadowsocksBinaryEligibility.Eligible,
        manifestRepository: EndpointManifestRepository? = manifestWithShadowsocksBinding(endpointA),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        shadowsocksTransport = shadowsocksTransport,
        shadowsocksCredentialRepositories = shadowsocksCredentialRepositories,
        shadowsocksBinaryEligibility = shadowsocksBinaryEligibility,
        manifestRepository = manifestRepository,
    )

    @Test
    fun `valid credential plus eligible ABI-binary - SHADOWSOCKS_2022 becomes AVAILABLE with the real registered instance`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.SHADOWSOCKS_2022)
        val viewModel = newViewModel(shadowsocksTransport = transport)
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.AVAILABLE, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        // The registered factory produces the EXACT SAME instance this
        // ViewModel was given - never a second/independently-constructed one.
        assertEquals(transport, registry.createTransport(TransportKind.SHADOWSOCKS_2022))
    }

    @Test
    fun `unsupported ABI - SHADOWSOCKS_2022 stays NOT_IMPLEMENTED even with a valid credential`() = runTest {
        val viewModel = newViewModel(
            shadowsocksBinaryEligibility = ShadowsocksBinaryEligibility.UnsupportedAbi(listOf("armeabi-v7a")),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        assertNull(registry.createTransport(TransportKind.SHADOWSOCKS_2022))
    }

    @Test
    fun `binary unavailable - SHADOWSOCKS_2022 stays NOT_IMPLEMENTED even with a valid credential`() = runTest {
        val viewModel = newViewModel(
            shadowsocksBinaryEligibility = ShadowsocksBinaryEligibility.BinaryUnavailable("not packaged"),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        assertNull(registry.createTransport(TransportKind.SHADOWSOCKS_2022))
    }

    @Test
    fun `missing credential - SHADOWSOCKS_2022 stays NOT_IMPLEMENTED even with an eligible ABI-binary`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(endpointA to FakeShadowsocks2022CredentialRepository(credential = null)),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `corrupted credential - SHADOWSOCKS_2022 stays NOT_IMPLEMENTED, never trusted just because a file exists`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(endpointA to FakeShadowsocks2022CredentialRepository(corrupted = true)),
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `no credential repository wired for any endpoint - stays NOT_IMPLEMENTED, no fabricated availability`() = runTest {
        val viewModel = newViewModel(shadowsocksCredentialRepositories = emptyMap())
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `no ShadowsocksTransport wired - descriptor absent entirely, same shape as every other unwired kind`() = runTest {
        val viewModel = newViewModel(shadowsocksTransport = null)
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertNull(registry.descriptorFor(TransportKind.SHADOWSOCKS_2022))
    }

    // --- Endpoint-scoping/isolation (review fix - no country/provider literal decides this) ---

    @Test
    fun `endpoint A has a real credential - A becomes eligible`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(endpointA to FakeShadowsocks2022CredentialRepository(validCredential(endpointA))),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `endpoint B has no wired repository at all - B stays ineligible`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(endpointA to FakeShadowsocks2022CredentialRepository(validCredential(endpointA))),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointB).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `A's credential never makes B eligible, even when B has a repository wired but no valid credential`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(
                endpointA to FakeShadowsocks2022CredentialRepository(validCredential(endpointA)),
                endpointB to FakeShadowsocks2022CredentialRepository(credential = null),
            ),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointB).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `multiple endpoints independently resolve their own credentials - both become eligible`() = runTest {
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(
                endpointA to FakeShadowsocks2022CredentialRepository(validCredential(endpointA)),
                endpointB to FakeShadowsocks2022CredentialRepository(validCredential(endpointB)),
            ),
            manifestRepository = manifestWithShadowsocksBinding(endpointA, endpointB),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(endpointB).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `Factory wiring is catalog-driven, not country-literal - proves both real catalog gateways are independently representable`() = runTest {
        val germany = ProductionGatewayCatalog.GERMANY.endpointId
        val stockholm = ProductionGatewayCatalog.STOCKHOLM.endpointId
        val viewModel = newViewModel(
            shadowsocksCredentialRepositories = mapOf(
                germany to FakeShadowsocks2022CredentialRepository(validCredential(germany)),
                stockholm to FakeShadowsocks2022CredentialRepository(credential = null),
            ),
            manifestRepository = manifestWithShadowsocksBinding(germany, stockholm),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry(germany).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(stockholm).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    // --- B45B-4P (correction): a device-local secret alone must never authorize an endpoint/port ---

    @Test
    fun `valid credential but no signed manifest binding at all - stays NOT_IMPLEMENTED, never AVAILABLE-then-fail-later`() = runTest {
        val viewModel = newViewModel(manifestRepository = null)
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `valid credential but manifest names a DIFFERENT endpoint - stays NOT_IMPLEMENTED for this one`() = runTest {
        val viewModel = newViewModel(manifestRepository = manifestWithShadowsocksBinding(endpointB))
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }

    @Test
    fun `valid credential but the manifest binding is Legacy (no typed Shadowsocks2022 profile) - stays NOT_IMPLEMENTED`() = runTest {
        val manifest = EndpointManifest(
            manifestVersion = 1,
            issuedAtEpochMillis = 1_000L,
            expiresAtEpochMillis = 9_000_000_000_000L,
            signingKeyId = "test-manifest-key",
            endpoints = listOf(
                EndpointDescriptor(
                    id = endpointA,
                    roles = setOf(EndpointRole.GATEWAY, EndpointRole.EXIT),
                    region = "test",
                    provider = "test",
                    // Right kind/host/port, but NO withShadowsocks2022Profile -
                    // signedTransportProfile() reads this as Legacy.
                    transports = listOf(EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "152.70.43.1", 28388)),
                ),
            ),
        )
        val signer = Ed25519Signer()
        signer.init(true, manifestSigningKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        val signed = SignedManifest(manifest, signer.generateSignature())
        val legacyManifestRepository = EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = manifestTrustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = signed,
            nowEpochMillis = { 2_000L },
        )
        val viewModel = newViewModel(manifestRepository = legacyManifestRepository)
        testDispatcher.scheduler.runCurrent()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry(endpointA).descriptorFor(TransportKind.SHADOWSOCKS_2022)?.status)
    }
}
