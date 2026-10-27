@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.XrayRealityXhttpProfile
import net.pocvpn.client.identity.XrayRealityXhttpProfileRepository
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
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.config.GatewayConfiguration
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
 * XRAY_REALITY_XHTTP registry eligibility: AVAILABLE only with BOTH a stored
 * profile that resolves Ready for the endpoint AND a trusted signed binding
 * for it - the manifest is the rollout switch. Same shape as
 * MainViewModelHysteria2SelectionTest.
 */
class MainViewModelRealityXhttpSelectionTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private class FakeRepository(private val profile: XrayRealityXhttpProfile?) : XrayRealityXhttpProfileRepository {
        override suspend fun getProfileOrNull(): XrayRealityXhttpProfile? = profile
        override suspend fun saveProfile(profile: XrayRealityXhttpProfile) = Unit
        override suspend fun clearProfile() = Unit
    }

    private val testDispatcher = StandardTestDispatcher()
    private val endpointA = EndpointId("endpoint-a")
    private val endpointB = EndpointId("endpoint-b")
    private val signingKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val trustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("test-manifest-key") to signingKey.generatePublicKey().encoded),
    )

    private val profile = XrayRealityXhttpProfile(
        server = "203.0.113.10", serverPort = 8443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "ab12cd34",
        xhttpPath = "/nova-rx/", mode = "packet-up", uplinkHttpMethod = "POST",
    )

    @Before
    fun setUp() = Dispatchers.setMain(testDispatcher)

    @After
    fun tearDown() = Dispatchers.resetMain()

    private fun manifest(kind: TransportKind, vararg endpointIds: EndpointId): EndpointManifestRepository {
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
                    transports = listOf(EndpointTransportBinding(kind, "203.0.113.10", 8443)),
                )
            },
        )
        val signer = Ed25519Signer()
        signer.init(true, signingKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = trustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = SignedManifest(manifest, signer.generateSignature()),
            nowEpochMillis = { 2_000L },
        )
    }

    private fun newViewModel(
        transport: FakeVpnTransport? = FakeVpnTransport(kind = TransportKind.XRAY_REALITY_XHTTP),
        repositories: Map<EndpointId, XrayRealityXhttpProfileRepository> = mapOf(endpointA to FakeRepository(profile)),
        manifestRepository: EndpointManifestRepository? = manifest(TransportKind.XRAY_REALITY_XHTTP, endpointA),
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        xrayRealityXhttpTransport = transport,
        xrayRealityXhttpProfileRepositories = repositories,
        manifestRepository = manifestRepository,
    ).also { testDispatcher.scheduler.runCurrent() }

    private fun statusFor(viewModel: MainViewModel, endpointId: EndpointId = endpointA) =
        viewModel.buildTransportRegistry(endpointId).descriptorFor(TransportKind.XRAY_REALITY_XHTTP)?.status

    @Test
    fun `stored profile plus trusted binding - AVAILABLE with the one registered instance`() = runTest {
        val transport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY_XHTTP)
        val viewModel = newViewModel(transport = transport)

        val registry = viewModel.buildTransportRegistry(endpointA)
        assertEquals(TransportStatus.AVAILABLE, registry.descriptorFor(TransportKind.XRAY_REALITY_XHTTP)?.status)
        assertEquals(transport, registry.createTransport(TransportKind.XRAY_REALITY_XHTTP))
    }

    @Test
    fun `a stored profile alone never makes it available without the signed binding`() = runTest {
        assertEquals(TransportStatus.NOT_IMPLEMENTED, statusFor(newViewModel(manifestRepository = manifest(TransportKind.XRAY_REALITY, endpointA))))
        assertEquals(TransportStatus.NOT_IMPLEMENTED, statusFor(newViewModel(manifestRepository = null)))
    }

    @Test
    fun `a signed binding alone never makes it available without a stored profile`() = runTest {
        assertEquals(TransportStatus.NOT_IMPLEMENTED, statusFor(newViewModel(repositories = mapOf(endpointA to FakeRepository(null)))))
        assertEquals(TransportStatus.NOT_IMPLEMENTED, statusFor(newViewModel(repositories = emptyMap())))
    }

    @Test
    fun `availability is per endpoint - a profile for one endpoint never enables another`() = runTest {
        val viewModel = newViewModel(manifestRepository = manifest(TransportKind.XRAY_REALITY_XHTTP, endpointA, endpointB))
        assertEquals(TransportStatus.AVAILABLE, statusFor(viewModel, endpointA))
        assertEquals(TransportStatus.NOT_IMPLEMENTED, statusFor(viewModel, endpointB))
    }

    @Test
    fun `no transport wired - descriptor falls back to the default NOT_IMPLEMENTED entry`() = runTest {
        val status = statusFor(newViewModel(transport = null))
        if (status != null) assertEquals(TransportStatus.NOT_IMPLEMENTED, status) else assertNull(status)
    }
}
