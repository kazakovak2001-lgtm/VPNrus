@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.XrayTlsProfileResult
import net.pocvpn.client.provisioning.toXrayProfile
import net.pocvpn.client.provisioning.toXrayTlsProfile
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
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayProfileRepository
import net.pocvpn.client.vpn.FakeXrayTlsProfileRepository
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.security.SecureRandom

/**
 * B13 THIRD consolidated review fix (finding 3) - reachabilityDiagnostics()
 * must resolve transport availability PER the endpoint each candidate
 * actually targets, never from one globally-selected endpoint's registry.
 * Germany's own Xray/TLS profile must never make a Stockholm candidate look
 * eligible, and vice versa. Purely observational - none of this promotes
 * PathScorer into Smart Connect's own decision.
 */
class MainViewModelMultiEndpointDiagnosticsTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()
    private val germanyEndpointId = ProductionGatewayCatalog.GERMANY.endpointId
    private val stockholmEndpointId = ProductionGatewayCatalog.STOCKHOLM.endpointId

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("key-1") to manifestSigningKey.generatePublicKey().encoded),
    )

    private fun twoEndpointManifest(kind: TransportKind) = EndpointManifest(
        manifestVersion = 1,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 9_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                germanyEndpointId, setOf(EndpointRole.GATEWAY), "Germany", "oracle",
                transports = listOf(EndpointTransportBinding(kind, "152.70.43.1", 443)),
            ),
            EndpointDescriptor(
                stockholmEndpointId, setOf(EndpointRole.GATEWAY), "Sweden", "aws",
                transports = listOf(EndpointTransportBinding(kind, "16.170.208.231", 443)),
            ),
        ),
    )

    private fun signTestManifest(manifest: EndpointManifest): SignedManifest {
        val signer = Ed25519Signer()
        signer.init(true, manifestSigningKey)
        val bytes = ManifestCanonicalizer.canonicalBytes(manifest)
        signer.update(bytes, 0, bytes.size)
        return SignedManifest(manifest, signer.generateSignature())
    }

    private fun testManifestRepository(manifest: EndpointManifest) = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = manifestTrustAnchors,
        lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
        bootstrapManifest = signTestManifest(manifest),
        nowEpochMillis = { 2_000L },
    )

    private val samplePofile = XrayProfileResult.Success(
        serverAddress = "152.70.43.1", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f", flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com", fingerprint = "chrome",
        realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    ).toXrayProfile()

    private val sampleTlsProfile = XrayTlsProfileResult.Success(
        serverAddress = "152.70.43.1", serverPort = 2083,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        serverName = "203.0.113.1", fingerprint = "chrome",
    ).toXrayTlsProfile()

    @Test
    fun `Germany-only Xray profile - Germany's XRAY_REALITY candidate is eligible, Stockholm's is not`() = runTest {
        val repository = testManifestRepository(twoEndpointManifest(TransportKind.XRAY_REALITY))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            manifestRepository = repository,
            xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY),
            xrayProfileRepository = FakeXrayProfileRepository(samplePofile),
            stockholmXrayProfileRepository = FakeXrayProfileRepository(profile = null),
        )
        testDispatcher.scheduler.advanceUntilIdle()

        val snapshot = viewModel.reachabilityDiagnostics()!!
        val germanyResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == germanyEndpointId } }
        val stockholmResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == stockholmEndpointId } }

        assertTrue("Germany's XRAY_REALITY candidate should be eligible", germanyResult.eligible)
        assertFalse("Stockholm's XRAY_REALITY candidate must NOT inherit Germany's availability", stockholmResult.eligible)
    }

    @Test
    fun `Stockholm-only Xray profile - Stockholm's candidate is eligible, Germany's is not`() = runTest {
        val repository = testManifestRepository(twoEndpointManifest(TransportKind.XRAY_REALITY))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            manifestRepository = repository,
            xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY),
            xrayProfileRepository = FakeXrayProfileRepository(profile = null),
            stockholmXrayProfileRepository = FakeXrayProfileRepository(samplePofile),
        )
        testDispatcher.scheduler.advanceUntilIdle()

        val snapshot = viewModel.reachabilityDiagnostics()!!
        val germanyResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == germanyEndpointId } }
        val stockholmResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == stockholmEndpointId } }

        assertFalse("Germany's XRAY_REALITY candidate must NOT inherit Stockholm's availability", germanyResult.eligible)
        assertTrue("Stockholm's XRAY_REALITY candidate should be eligible", stockholmResult.eligible)
    }

    @Test
    fun `Germany-only TLS profile - Germany's TLS_TCP candidate is eligible, Stockholm's is not - the symmetric TLS path`() = runTest {
        val repository = testManifestRepository(twoEndpointManifest(TransportKind.TLS_TCP))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            manifestRepository = repository,
            xrayTlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP),
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(sampleTlsProfile),
            stockholmXrayTlsProfileRepository = FakeXrayTlsProfileRepository(profile = null),
        )
        testDispatcher.scheduler.advanceUntilIdle()

        val snapshot = viewModel.reachabilityDiagnostics()!!
        val germanyResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == germanyEndpointId } }
        val stockholmResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == stockholmEndpointId } }

        assertTrue("Germany's TLS_TCP candidate should be eligible", germanyResult.eligible)
        assertFalse("Stockholm's TLS_TCP candidate must NOT inherit Germany's availability", stockholmResult.eligible)
    }

    @Test
    fun `Stockholm-only TLS profile - Stockholm's TLS_TCP candidate is eligible, Germany's is not`() = runTest {
        val repository = testManifestRepository(twoEndpointManifest(TransportKind.TLS_TCP))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            manifestRepository = repository,
            xrayTlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP),
            xrayTlsProfileRepository = FakeXrayTlsProfileRepository(profile = null),
            stockholmXrayTlsProfileRepository = FakeXrayTlsProfileRepository(sampleTlsProfile),
        )
        testDispatcher.scheduler.advanceUntilIdle()

        val snapshot = viewModel.reachabilityDiagnostics()!!
        val germanyResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == germanyEndpointId } }
        val stockholmResult = snapshot.rankedPaths.first { it.candidate.hops.any { hop -> hop.endpoint.id == stockholmEndpointId } }

        assertFalse("Germany's TLS_TCP candidate must NOT inherit Stockholm's availability", germanyResult.eligible)
        assertTrue("Stockholm's TLS_TCP candidate should be eligible", stockholmResult.eligible)
    }
}
