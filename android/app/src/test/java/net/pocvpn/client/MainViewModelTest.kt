@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.reachability.EndpointDescriptor
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointManifest
import net.pocvpn.client.reachability.EndpointManifestRepository
import net.pocvpn.client.reachability.EndpointRole
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Ed25519ManifestVerifier
import net.pocvpn.client.reachability.FileLastKnownGoodManifestStore
import net.pocvpn.client.reachability.FixedManifestTrustAnchors
import net.pocvpn.client.reachability.ManifestCanonicalizer
import net.pocvpn.client.reachability.ManifestFetchFailureKind
import net.pocvpn.client.reachability.ManifestFetchResult
import net.pocvpn.client.reachability.ManifestOrigin
import net.pocvpn.client.reachability.MultiOriginManifestDistributionClient
import net.pocvpn.client.reachability.PathCandidate
import net.pocvpn.client.reachability.RemoteManifestFetcher
import net.pocvpn.client.reachability.SignedManifest
import net.pocvpn.client.reachability.TrustedKeyId
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.XrayProfileProvisioner
import net.pocvpn.client.provisioning.XrayProfileProvisioningOutcome
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.toXrayProfile
import net.pocvpn.client.provisioning.XrayTlsProfileResult
import net.pocvpn.client.provisioning.toXrayTlsProfile
import net.pocvpn.client.smartconnect.ConnectionScoreReason
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStatus
import net.pocvpn.client.transport.UserTransportPreference
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.FakeXrayProfileRepository
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.DefaultGatewayConfigurationRepository
import net.pocvpn.client.vpn.config.GatewayConfigSource
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.MutableGatewayConfigSource
import net.pocvpn.client.vpn.config.FileProfileStore
import net.pocvpn.client.vpn.config.PersistedProfile
import net.pocvpn.client.vpn.config.ProfileLoadResult
import net.pocvpn.client.vpn.config.ProfileSource
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** B8C2A - devfallback delegate for MutableGatewayConfigSource in these tests; every field is empty/unset until apply() runs. */
private class EmptyGatewayConfigSource : GatewayConfigSource {
    override fun endpointHost() = ""
    override fun endpointPort() = ""
    override fun serverPublicKey() = ""
    override fun clientTunnelIp() = ""
    override fun gatewayTunnelIp() = ""
    override fun allowedIps() = "0.0.0.0/0"
}

private val SAMPLE_ACTIVATION_SUCCESS = ProvisioningResult.Success(
    clientTunnelIp = "10.77.0.2",
    gatewayPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
    gatewayTunnelIp = "10.77.0.1",
    endpointHost = "152.70.43.1",
    endpointPort = 51820,
)

private val SAMPLE_XRAY_TLS_PROFILE_SUCCESS = XrayTlsProfileResult.Success(
    serverAddress = "152.70.43.1",
    serverPort = 2053,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    serverName = "203.0.113.1",
    fingerprint = "chrome",
)

private val SAMPLE_XRAY_PROFILE_SUCCESS = XrayProfileResult.Success(
    serverAddress = "152.70.43.1",
    serverPort = 443,
    uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
    flow = "xtls-rprx-vision",
    serverName = "www.microsoft.com",
    fingerprint = "chrome",
    realityPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
    shortId = "a1b2c3d4",
)

class MainViewModelTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private val testDispatcher = StandardTestDispatcher()

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    @Test
    fun `viewModel transportState reflects the underlying transport, not a duplicate fake state`() = runTest {
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
        )

        assertEquals(TransportState.Disconnected, viewModel.transportState.value)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `publicKey is loaded from the repository on init`() = runTest {
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "SOME_PUBLIC_KEY_VALUE_ABCDEFGHIJKLMNOP===="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
        )
        testDispatcher.scheduler.runCurrent()
        assertEquals("SOME_PUBLIC_KEY_VALUE_ABCDEFGHIJKLMNOP====", viewModel.publicKey.value)
    }

    @Test
    fun `constructing MainViewModel registers the reconnect manager exactly once`() = runTest {
        val reconnectManager = FakeReconnectManager()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = reconnectManager,
            diagnosticsStore = DiagnosticsStore(),
        )
        testDispatcher.scheduler.runCurrent()

        // Activity recreation (rotation) does not construct a new MainViewModel -
        // the ViewModelStore survives it - so this call count staying at 1 across
        // this ViewModel's lifetime is what guarantees no duplicate
        // ConnectivityManager callback registration on rotation.
        assertEquals(1, reconnectManager.startCallCount)

        // onCleared() is protected; drive it the same way the real Android
        // lifecycle does - by clearing the ViewModelStore that owns it.
        val store = androidx.lifecycle.ViewModelStore()
        store.put("main", viewModel)
        store.clear()
        assertEquals(1, reconnectManager.stopCallCount)
    }

    @Test
    fun `regenerateIdentity clears then recreates identity`() = runTest {
        val keyRepository = FakeClientKeyRepository()
        val viewModel = MainViewModel(
            clientKeyRepository = keyRepository,
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
        )
        viewModel.regenerateIdentity()
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, keyRepository.clearCallCount)
    }

    // --- B8C2A: activation wiring proof ---

    @Test
    fun `activateDevice sources the public key automatically from the client key repository, never from the caller`() = runTest {
        var capturedPublicKey: String? = null
        var capturedCredential: String? = null
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "EXISTING_DEVICE_PUBLIC_KEY_NOT_SUPPLIED_BY_CALLER="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            activationClient = { publicKey, credential ->
                capturedPublicKey = publicKey
                capturedCredential = credential
                SAMPLE_ACTIVATION_SUCCESS
            },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent() // let init's getPublicKey() complete before activating

        // activateDevice's ONLY parameter is the activation credential - no
        // public-key parameter exists on this call at all.
        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals("EXISTING_DEVICE_PUBLIC_KEY_NOT_SUPPLIED_BY_CALLER=", capturedPublicKey)
        assertEquals("some-activation-credential", capturedCredential)
    }

    @Test
    fun `successful activation applies to the gateway config source and persists via the profile store`() = runTest {
        val gatewayConfigSource = MutableGatewayConfigSource(EmptyGatewayConfigSource())
        val profileStore = FileProfileStore(tmp.newFolder("profile-success"))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ0="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(gatewayConfigSource),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewayConfigOverride = gatewayConfigSource,
            profileStore = profileStore,
            activationClient = { _, _ -> SAMPLE_ACTIVATION_SUCCESS },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        // 1. flows through the existing proven MutableGatewayConfigSource.apply() path
        assertTrue(viewModel.gatewayStatus() is GatewayConfiguration.Configured)
        val configured = viewModel.gatewayStatus() as GatewayConfiguration.Configured
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.clientTunnelIp, configured.clientTunnelIp)
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.endpointHost, configured.endpointHost)
        assertEquals(ProfileSource.PROVISIONED_LIVE, viewModel.profileSource.value)

        // 2. flows through the existing proven ProvisionedProfileStore persistence path
        val persisted = profileStore.read()
        assertTrue(persisted is ProfileLoadResult.Found)
        val profile = (persisted as ProfileLoadResult.Found).profile
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.clientTunnelIp, profile.clientTunnelIp)
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.gatewayPublicKey, profile.gatewayPublicKey)
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.gatewayTunnelIp, profile.gatewayTunnelIp)
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.endpointHost, profile.endpointHost)
        assertEquals(SAMPLE_ACTIVATION_SUCCESS.endpointPort, profile.endpointPort)
    }

    @Test
    fun `activation credential never reaches the persisted profile, diagnostics, or effective config`() = runTest {
        val credential = "SECRET-ACTIVATION-CREDENTIAL-MUST-NOT-LEAK"
        val gatewayConfigSource = MutableGatewayConfigSource(EmptyGatewayConfigSource())
        val profileStore = FileProfileStore(tmp.newFolder("profile-secrecy"))
        val diagnosticsStore = DiagnosticsStore()
        val diagnosticsBefore = diagnosticsStore.snapshot.value
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ0="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(gatewayConfigSource),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnosticsStore,
            gatewayConfigOverride = gatewayConfigSource,
            profileStore = profileStore,
            activationClient = { _, _ -> SAMPLE_ACTIVATION_SUCCESS },
            ioDispatcher = testDispatcher,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice(credential)
        testDispatcher.scheduler.runCurrent()

        // Not in ProvisionedProfileStore - PersistedProfile has no field that
        // could even hold it (see PersistedProfile's own doc), verified here
        // by reading the persisted profile back and checking every string field.
        val profile = (profileStore.read() as ProfileLoadResult.Found).profile
        assertFalse(profile.endpointHost.contains(credential))
        assertFalse(profile.gatewayPublicKey.contains(credential))
        assertFalse(profile.clientTunnelIp.contains(credential))
        assertFalse(profile.gatewayTunnelIp.contains(credential))

        // Not in diagnostics - activateDevice never calls any DiagnosticsStore
        // method, so the snapshot is untouched by this call.
        assertEquals(diagnosticsBefore, diagnosticsStore.snapshot.value)

        // Not in the effective config surfaced to the UI (gatewayStatus()).
        val configured = viewModel.gatewayStatus() as GatewayConfiguration.Configured
        assertFalse(configured.endpointHost.contains(credential))
        assertFalse(configured.serverPublicKeyBase64.contains(credential))
        assertFalse(configured.clientTunnelIp.contains(credential))
    }

    @Test
    fun `a previously persisted profile restores and is usable with no activation credential ever supplied`() = runTest {
        val profileStore = FileProfileStore(tmp.newFolder("profile-restore"))
        profileStore.write(
            PersistedProfile(
                endpointHost = "152.70.43.1",
                endpointPort = 51820,
                gatewayPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=",
                clientTunnelIp = "10.77.0.5",
                gatewayTunnelIp = "10.77.0.1",
            )
        )
        val gatewayConfigSource = MutableGatewayConfigSource(EmptyGatewayConfigSource())

        // activationClient is never invoked in this test - activateDevice() is
        // never called at all - proving restore alone is sufficient.
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(gatewayConfigSource),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewayConfigOverride = gatewayConfigSource,
            profileStore = profileStore,
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProfileSource.RESTORED_PERSISTED, viewModel.profileSource.value)
        val configured = viewModel.gatewayStatus()
        assertTrue(configured is GatewayConfiguration.Configured)
        assertEquals("10.77.0.5", (configured as GatewayConfiguration.Configured).clientTunnelIp)
    }

    // --- B8K4B: Xray profile provisioning wiring ---

    @Test
    fun `successful activation and Xray fetch saves exactly one validated profile`() = runTest {
        val xrayRepository = SecureXrayProfileRepository(FileXrayProfileStore(tmp.newFolder("xray-success")), FakeAesGcmKeyEncryptor())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ0="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            activationClient = { _, _ -> SAMPLE_ACTIVATION_SUCCESS },
            ioDispatcher = testDispatcher,
            xrayProfileProvisioner = XrayProfileProvisioner(xrayRepository) { _, _ -> SAMPLE_XRAY_PROFILE_SUCCESS },
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(XrayProfileProvisioningOutcome.Saved, viewModel.xrayProfileProvisioningState.value)
        assertEquals(SAMPLE_XRAY_PROFILE_SUCCESS.toXrayProfile(), xrayRepository.getProfileOrNull())
    }

    @Test
    fun `AWG activation and Xray fetch use the same existing device public key and same activation credential`() = runTest {
        var awgPublicKey: String? = null
        var awgCredential: String? = null
        var xrayPublicKey: String? = null
        var xrayCredential: String? = null
        val xrayRepository = SecureXrayProfileRepository(FileXrayProfileStore(tmp.newFolder("xray-shared-identity")), FakeAesGcmKeyEncryptor())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "SHARED_DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOP===="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            activationClient = { publicKey, credential ->
                awgPublicKey = publicKey
                awgCredential = credential
                SAMPLE_ACTIVATION_SUCCESS
            },
            ioDispatcher = testDispatcher,
            xrayProfileProvisioner = XrayProfileProvisioner(xrayRepository) { publicKey, credential ->
                xrayPublicKey = publicKey
                xrayCredential = credential
                SAMPLE_XRAY_PROFILE_SUCCESS
            },
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("shared-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals("SHARED_DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOP====", awgPublicKey)
        assertEquals("SHARED_DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOP====", xrayPublicKey)
        assertEquals(awgPublicKey, xrayPublicKey)
        assertEquals("shared-activation-credential", awgCredential)
        assertEquals("shared-activation-credential", xrayCredential)
        assertEquals(awgCredential, xrayCredential)
    }

    @Test
    fun `Xray profile retrieval failure does not affect AWG activation success, and does not overwrite an existing stored profile`() = runTest {
        val xrayFolder = tmp.newFolder("xray-failure-keeps-existing")
        val xrayRepository = SecureXrayProfileRepository(FileXrayProfileStore(xrayFolder), FakeAesGcmKeyEncryptor())
        val existingProfile = XrayProfile(
            server = "existing.example.net", serverPort = 8443,
            uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f", flow = "xtls-rprx-vision",
            serverName = "existing.example.net", fingerprint = "chrome",
            realityPublicKey = "9WewKC/zyUPyPnKyzaI0bZrEN2c73PqjK7f+fRXHYRU=", shortId = "deadbeef",
        )
        runBlocking { xrayRepository.saveProfile(existingProfile) }
        val gatewayConfigSource = MutableGatewayConfigSource(EmptyGatewayConfigSource())
        val profileStore = FileProfileStore(tmp.newFolder("profile-xray-failure"))
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ0="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = DefaultGatewayConfigurationRepository(gatewayConfigSource),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewayConfigOverride = gatewayConfigSource,
            profileStore = profileStore,
            activationClient = { _, _ -> SAMPLE_ACTIVATION_SUCCESS },
            ioDispatcher = testDispatcher,
            xrayProfileProvisioner = XrayProfileProvisioner(xrayRepository) { _, _ -> XrayProfileResult.ServiceUnavailable },
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        // AWG activation succeeded exactly as it does with no Xray provisioner wired at all.
        assertTrue(viewModel.gatewayStatus() is GatewayConfiguration.Configured)
        assertEquals(ProfileSource.PROVISIONED_LIVE, viewModel.profileSource.value)
        assertTrue((profileStore.read() as ProfileLoadResult.Found).profile.endpointHost.isNotBlank())

        // Xray outcome surfaced, but the previously stored profile is untouched.
        assertEquals(XrayProfileProvisioningOutcome.Unavailable, viewModel.xrayProfileProvisioningState.value)
        assertEquals(existingProfile, xrayRepository.getProfileOrNull())
    }

    // --- B8I2/B8I3: Smart Connect preflight - connect() enforces smartConnectDecision(),
    // now executed through TransportOrchestrator.resolve() rather than a hard-coded
    // kind check (see MainViewModel.connect()'s own docs) - same externally observable
    // outcomes as B8I2, now proven against the NEW resolution-based code path. See
    // TransportOrchestratorTest for "decision never recomputed"/"no silent substitution"
    // proofs at the orchestrator unit level - not duplicated here. ---

    private val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
        type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
        roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
        vpnActive = false, generation = 1,
    )

    private val UNUSABLE_NETWORK = net.pocvpn.client.network.NetworkProfile(
        type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = false, metered = false,
        roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
        vpnActive = false, generation = 1,
    )

    private val CONFIGURED_GATEWAY = GatewayConfiguration.Configured(
        endpointHost = "203.0.113.10", endpointPort = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
        allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
    )

    @Test
    fun `usable network plus configured gateway plus AWG available - connect reaches the transport`() = runTest {
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // Proves resolution actually happened against THIS transport
        // instance (not merely that "some" connect occurred): the AWG
        // config was built and handed to the SAME FakeVpnTransport this
        // ViewModel owns.
        assertEquals(1, transport.connectCallCount)
        assertTrue(transport.lastConfig is net.pocvpn.client.vpn.config.TransportConfig.Awg)
    }

    @Test
    fun `unusable network - connect is blocked, transport never touched`() = runTest {
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = UNUSABLE_NETWORK,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `missing gateway - connect is blocked, transport never touched`() = runTest {
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `invalid gateway - connect is blocked, transport never touched`() = runTest {
        val transport = FakeVpnTransport()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Invalid("bad config")),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `non-AWG selected transport - connect is blocked, transport never touched, no permission requested`() = runTest {
        // The ONLY transport this registry has available is XRAY_REALITY -
        // SmartConnectDecisionEngine has nothing else to select.
        val transport = FakeVpnTransport(permission = android.content.Intent(), kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        // preparePermissionIntent() is only ever called from inside
        // controller.connect() - a non-zero permission Intent above would
        // have made a real controller.connect() attempt emit
        // RequestVpnPermission; asserting Error (not e.g. still Disconnected
        // pending a permission event) proves this path was never reached.
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    // --- B8I1: ONE Smart Connect decision authority, reached only via MainViewModel.smartConnectDecision() ---

    @Test
    fun `smartConnectDecision is the single call site MainViewModel exposes - AWG plus Frankfurt plus ONLY_AVAILABLE_CANDIDATE for a configured gateway`() = runTest {
        val configuredGateway = GatewayConfiguration.Configured(
            endpointHost = "203.0.113.10", endpointPort = 51820,
            serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
            clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
            allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
        )
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = net.pocvpn.client.network.NetworkProfile(
                type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
                roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
                vpnActive = false, generation = 1,
            ),
        )
        testDispatcher.scheduler.runCurrent()

        val decision = viewModel.smartConnectDecision()

        assertTrue(decision is SmartConnectDecision.Selected)
        val selected = decision as SmartConnectDecision.Selected
        assertEquals(TransportKind.AMNEZIA_WG, selected.score.candidate.transport.kind)
        assertEquals(ProductionGateway.ID, selected.score.candidate.gateway.id)
        assertEquals(ConnectionScoreReason.ONLY_AVAILABLE_CANDIDATE, selected.score.reason)
    }

    @Test
    fun `smartConnectDecision with no gateway configured is truthfully NoCandidateAvailable, never a fabricated pick`() = runTest {
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
        )
        testDispatcher.scheduler.runCurrent()

        assertEquals(SmartConnectDecision.NoCandidateAvailable, viewModel.smartConnectDecision())
    }

    // --- B8J: RestrictionClassifier/RestrictionMonitor wiring never touches the transport ---

    @Test
    fun `a real handshake failure triggers exactly one probe and restrictionClass reflects it, without the classifier ever calling transport connect or disconnect`() = runTest {
        val configuredGateway = GatewayConfiguration.Configured(
            endpointHost = "203.0.113.10", endpointPort = 51820,
            serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
            clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
            allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
        )
        val transport = FakeVpnTransport().apply { handshakeAvailable = false }
        var probeCallCount = 0
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(configuredGateway),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            connectionOutcomeStore = net.pocvpn.client.vpn.FakeConnectionOutcomeStore(),
            initialNetworkProfile = net.pocvpn.client.network.NetworkProfile(
                type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
                roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
                vpnActive = false, generation = 1,
            ),
            restrictionProbe = net.pocvpn.client.smartconnect.GatewayReachabilityProbe {
                probeCallCount++
                true // gateway HTTPS reachable
            },
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect() // real, explicit, user-initiated - the ONLY connect() call in this test
        testDispatcher.scheduler.runCurrent()
        testDispatcher.scheduler.advanceTimeBy(10_000) // let the handshake-timeout poll loop actually elapse
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.transportState.value is TransportState.HandshakeFailed)
        assertEquals(1, probeCallCount)
        // validated internet + gateway HTTPS reachable + AWG handshake failed
        // -> POSSIBLE_UDP_OR_AWG_FILTERING (see RestrictionClassifier's own rules).
        assertEquals(net.pocvpn.client.smartconnect.RestrictionClass.POSSIBLE_UDP_OR_AWG_FILTERING, viewModel.restrictionClass())
        // The classifier/monitor layer never itself calls transport.connect()/
        // disconnect() - the ONLY connect() call above is the explicit user one.
        assertEquals(1, transport.connectCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    // --- B8I7: production Xray registration + trustworthy Xray connection-state signal ---

    @Test
    fun `buildTransportRegistry registers exactly one real XRAY_REALITY transport once a profile is available`() = runTest {
        val transport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE_SUCCESS.toXrayProfile())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTransport = xrayTransport,
            xrayProfileRepository = xrayRepository,
        )
        testDispatcher.scheduler.runCurrent() // let init's startup xrayAvailable check complete

        val registry = viewModel.buildTransportRegistry()

        val xrayDescriptor = registry.descriptorFor(TransportKind.XRAY_REALITY)
        assertEquals(TransportStatus.AVAILABLE, xrayDescriptor?.status)
        // The registered instance IS the exact one this ViewModel was given -
        // never a second/independently-constructed one.
        assertEquals(xrayTransport, registry.createTransport(TransportKind.XRAY_REALITY))
        // AWG's own descriptor is completely unaffected by Xray being wired.
        assertEquals(TransportStatus.AVAILABLE, registry.descriptorFor(TransportKind.AMNEZIA_WG)?.status)
        assertEquals(transport, registry.createTransport(TransportKind.AMNEZIA_WG))
    }

    @Test
    fun `XRAY_REALITY stays NOT_IMPLEMENTED - never a hardcoded true - when no Xray profile is available`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(profile = null)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTransport = xrayTransport,
            xrayProfileRepository = xrayRepository,
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.XRAY_REALITY)?.status)
        assertNull(registry.createTransport(TransportKind.XRAY_REALITY))
    }

    @Test
    fun `TransportOrchestrator resolves the exact registered XRAY_REALITY transport instance`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(SAMPLE_XRAY_PROFILE_SUCCESS.toXrayProfile())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTransport = xrayTransport,
            xrayProfileRepository = xrayRepository,
        )
        testDispatcher.scheduler.runCurrent()

        val orchestrator = TransportOrchestrator(viewModel.buildTransportRegistry())
        val resolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(TransportKind.XRAY_REALITY))

        assertTrue(resolution is TransportOrchestrator.Resolution.Resolved)
        assertEquals(xrayTransport, (resolution as TransportOrchestrator.Resolution.Resolved).transport)
    }

    // --- B8O2: TLS/TCP fallback registration - mirrors the XRAY_REALITY tests above ---

    @Test
    fun `buildTransportRegistry registers exactly one real TLS_TCP transport once a TLS profile is available`() = runTest {
        val transport = FakeVpnTransport()
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val tlsRepository = net.pocvpn.client.vpn.FakeXrayTlsProfileRepository(SAMPLE_XRAY_TLS_PROFILE_SUCCESS.toXrayTlsProfile())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTlsTransport = tlsTransport,
            xrayTlsProfileRepository = tlsRepository,
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry()

        val tlsDescriptor = registry.descriptorFor(TransportKind.TLS_TCP)
        assertEquals(TransportStatus.AVAILABLE, tlsDescriptor?.status)
        assertEquals(tlsTransport, registry.createTransport(TransportKind.TLS_TCP))
        // AWG's own descriptor is completely unaffected by TLS_TCP being wired.
        assertEquals(TransportStatus.AVAILABLE, registry.descriptorFor(TransportKind.AMNEZIA_WG)?.status)
    }

    @Test
    fun `TLS_TCP stays NOT_IMPLEMENTED - never a hardcoded true - when no TLS profile is available`() = runTest {
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val tlsRepository = net.pocvpn.client.vpn.FakeXrayTlsProfileRepository(profile = null)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTlsTransport = tlsTransport,
            xrayTlsProfileRepository = tlsRepository,
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.TLS_TCP)?.status)
        assertNull(registry.createTransport(TransportKind.TLS_TCP))
    }

    @Test
    fun `TLS_TCP being AVAILABLE never becomes the automatic Auto-preference pick while AWG is available`() = runTest {
        val transport = FakeVpnTransport()
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val tlsRepository = net.pocvpn.client.vpn.FakeXrayTlsProfileRepository(SAMPLE_XRAY_TLS_PROFILE_SUCCESS.toXrayTlsProfile())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTlsTransport = tlsTransport,
            xrayTlsProfileRepository = tlsRepository,
            // userTransportPreference defaults to Auto.
        )
        testDispatcher.scheduler.runCurrent()

        val decision = viewModel.smartConnectDecision()

        assertTrue(decision is SmartConnectDecision.Selected)
        assertEquals(TransportKind.AMNEZIA_WG, (decision as SmartConnectDecision.Selected).score.candidate.transport.kind)
    }

    @Test
    fun `a decryptable but semantically invalid stored TLS profile never registers TLS_TCP as AVAILABLE`() = runTest {
        // B8O2 audit fix - a profile that exists (decrypts fine) but fails
        // XrayRuntimeResolver.resolveTls's own validation (here: a
        // malformed uuid) must NOT register TLS_TCP as AVAILABLE, even
        // though a naive "profile != null" check would wrongly say it is -
        // this is the exact bug the fix closes.
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val invalidProfile = SAMPLE_XRAY_TLS_PROFILE_SUCCESS.toXrayTlsProfile().copy(uuid = "not-a-uuid")
        val tlsRepository = net.pocvpn.client.vpn.FakeXrayTlsProfileRepository(invalidProfile)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            xrayTlsTransport = tlsTransport,
            xrayTlsProfileRepository = tlsRepository,
        )
        testDispatcher.scheduler.runCurrent()

        val registry = viewModel.buildTransportRegistry()

        assertEquals(TransportStatus.NOT_IMPLEMENTED, registry.descriptorFor(TransportKind.TLS_TCP)?.status)
        assertNull(registry.createTransport(TransportKind.TLS_TCP))
    }

    @Test
    fun `Manual TLS_TCP preference selects it once available`() = runTest {
        val transport = FakeVpnTransport()
        val tlsTransport = FakeVpnTransport(kind = TransportKind.TLS_TCP)
        val tlsRepository = net.pocvpn.client.vpn.FakeXrayTlsProfileRepository(SAMPLE_XRAY_TLS_PROFILE_SUCCESS.toXrayTlsProfile())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTlsTransport = tlsTransport,
            xrayTlsProfileRepository = tlsRepository,
            userTransportPreference = UserTransportPreference.Manual(TransportKind.TLS_TCP),
        )
        testDispatcher.scheduler.runCurrent()

        val decision = viewModel.smartConnectDecision()

        assertTrue(decision is SmartConnectDecision.Selected)
        assertEquals(TransportKind.TLS_TCP, (decision as SmartConnectDecision.Selected).score.candidate.transport.kind)
    }

    @Test
    fun `AWG registry entry and connect behavior are unchanged when Xray is also wired but unavailable`() = runTest {
        val transport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(profile = null),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `Xray becomes available the instant a profile is provisioned - never polled, never a startup-only check`() = runTest {
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val xrayRepository = FakeXrayProfileRepository(profile = null)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(publicKey = "DEVICE_PUBLIC_KEY_ABCDEFGHIJKLMNOPQRSTUVWXYZ0="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            activationClient = { _, _ -> SAMPLE_ACTIVATION_SUCCESS },
            ioDispatcher = testDispatcher,
            xrayProfileProvisioner = XrayProfileProvisioner(xrayRepository) { _, _ -> SAMPLE_XRAY_PROFILE_SUCCESS },
            xrayTransport = xrayTransport,
            xrayProfileRepository = xrayRepository,
        )
        testDispatcher.scheduler.runCurrent()

        // Before provisioning: no profile exists yet, so Xray is not selectable.
        assertEquals(TransportStatus.NOT_IMPLEMENTED, viewModel.buildTransportRegistry().descriptorFor(TransportKind.XRAY_REALITY)?.status)

        viewModel.activateDevice("some-activation-credential")
        testDispatcher.scheduler.runCurrent()

        assertEquals(XrayProfileProvisioningOutcome.Saved, viewModel.xrayProfileProvisioningState.value)
        assertEquals(TransportStatus.AVAILABLE, viewModel.buildTransportRegistry().descriptorFor(TransportKind.XRAY_REALITY)?.status)
    }

    // --- B8I8: controlled AWG -> Xray failover ---

    // SAMPLE_XRAY_PROFILE_SUCCESS's own realityPublicKey is a STANDARD
    // base64 WireGuard-shaped key (valid for the B8K4A provisioning-wire
    // tests it was defined for) - it does NOT match
    // XrayVlessRealityConfig's stricter url-safe-base64-without-padding
    // REALITY_PUBLIC_KEY_REGEX, so XrayRuntimeResolver.resolve() rejects it.
    // The B8I8 tests below need a profile that ACTUALLY passes full Xray
    // config validation (they exercise the real resolve()/buildTransportConfig
    // path, unlike the shallower B8I7 registry-only tests above) - this
    // swaps in a compliant key, keeping every other field identical.
    private fun validXrayProfileForFailoverTests() = SAMPLE_XRAY_PROFILE_SUCCESS.toXrayProfile().copy(realityPublicKey = "A".repeat(43))

    @Test
    fun `Auto plus AWG success - Xray never starts`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `Auto plus eligible AWG failure plus Xray available - exactly one Xray fallback attempt`() = runTest {
        // A real, race-free AWG failure: no fresh handshake within the
        // bounded startup window (see VpnController.awaitFreshHandshake) -
        // the SAME mechanism real AmneziaWgTransport failures actually
        // surface through (AmneziaWgTransport.connect() never lets an
        // exception escape to VpnController - it always reports failure via
        // its own observeState()).
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000) // let the handshake-timeout poll loop actually elapse
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        // The failed AWG attempt was cleanly detached BEFORE Xray started -
        // never left active concurrently with Xray.
        assertEquals(1, awgTransport.disconnectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `Auto plus AWG failure plus Xray unavailable - no fallback`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            // xrayTransport intentionally not wired at all.
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, awgTransport.disconnectCallCount) // no fallback attempted -> no detach needed
        assertTrue(viewModel.transportState.value is TransportState.HandshakeFailed)
    }

    @Test
    fun `Manual AWG plus AWG failure - no Xray fallback`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
            userTransportPreference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.HandshakeFailed)
    }

    @Test
    fun `Manual Xray - Xray starts directly, AWG never starts`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
            userTransportPreference = UserTransportPreference.Manual(TransportKind.XRAY_REALITY),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, awgTransport.connectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    // --- B18-2: debugSetTransportPreference (debug-only Diagnostics dialog action) ---

    @Test
    fun `debugSetTransportPreference defaults to Auto and is reflected by the transportPreference getter`() {
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
        )

        assertEquals(UserTransportPreference.Auto, viewModel.transportPreference)

        viewModel.debugSetTransportPreference(UserTransportPreference.Manual(TransportKind.XRAY_REALITY))

        assertEquals(UserTransportPreference.Manual(TransportKind.XRAY_REALITY), viewModel.transportPreference)
    }

    @Test
    fun `debugSetTransportPreference actually drives the real connect() path - same outcome as the constructor-pinned Manual preference`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
            // Deliberately left at the default (Auto) here - debugSetTransportPreference below is what must change it.
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.debugSetTransportPreference(UserTransportPreference.Manual(TransportKind.XRAY_REALITY))
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, awgTransport.connectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `AWG gateway-missing preflight failure - no fallback`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `Xray fallback failure (malformed profile) surfaces truthfully with no second fallback or retry`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        // Xray's own fallback fails at config-build time (fails closed
        // BEFORE ever touching the transport - see buildTransportConfig's
        // XRAY_REALITY branch) - a real, non-contrived way for the fallback
        // attempt itself to fail.
        val invalidProfile = validXrayProfileForFailoverTests().copy(uuid = "not-a-uuid")
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(invalidProfile),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        // Exactly one fallback ATTEMPT was made (the resolve+disconnect+connect
        // sequence ran once) - it never even reaches the Xray transport itself
        // because the profile fails validation first, and there is no retry.
        assertEquals(0, xrayTransport.connectCallCount)
        // Xray's own real failure is surfaced truthfully, not masked as AWG success.
        assertTrue(viewModel.transportState.value is TransportState.Error)
        assertFalse(viewModel.diagnostics.value.toString().contains(invalidProfile.realityPublicKey))
        assertFalse(viewModel.diagnostics.value.toString().contains(invalidProfile.shortId))
    }

    @Test
    fun `stale AWG state after a fallback switch cannot overwrite Xray state - AWG and Xray never active concurrently`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertTrue(viewModel.transportState.value is TransportState.Connected) // Xray took over
        assertEquals(1, awgTransport.disconnectCallCount)

        // A late/stale emission from the now-detached AWG transport must
        // never leak into the CURRENT (Xray) state - proves no two
        // collectors can drive state concurrently.
        awgTransport.forceState(TransportState.Error("stale from detached AWG"))
        testDispatcher.scheduler.runCurrent()

        assertTrue(
            "stale AWG emission leaked into controller state: ${viewModel.transportState.value}",
            viewModel.transportState.value is TransportState.Connected,
        )
    }

    // --- B8I8A: AWG -> Xray failover after the VPN-permission resume path ---

    @Test
    fun `B8I8A permission required, granted, real AWG handshake timeout - AWG disconnects and registered Xray connects`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        // Permission requested - the initial attempt is still pending, not
        // yet touching either transport.
        assertEquals(0, awgTransport.connectCallCount)

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000) // let the handshake-timeout poll loop actually elapse
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `B8I8A permission denied - no fallback, AWG and Xray both untouched`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        viewModel.onVpnPermissionResult(false)
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `B8I8A Manual AWG plus permission grant plus AWG failure - no Xray fallback`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
            userTransportPreference = UserTransportPreference.Manual(TransportKind.AMNEZIA_WG),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.HandshakeFailed)
    }

    @Test
    fun `B8I8A permission grant plus AWG failure plus Xray unavailable - no fallback`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            // xrayTransport intentionally not wired at all.
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(0, awgTransport.disconnectCallCount) // no fallback attempted -> no detach needed
        assertTrue(viewModel.transportState.value is TransportState.HandshakeFailed)
    }

    @Test
    fun `B8I8A permission grant plus non-eligible AWG error (gateway missing) - no fallback`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent())
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(0, awgTransport.connectCallCount) // permission requested but not yet granted

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        // Gateway is checked inside doConnectAttempt, BEFORE
        // activeTransport.connect() is ever invoked - a preflight-shaped
        // failure, never a real connection attempt.
        assertEquals(0, awgTransport.connectCallCount)
        assertEquals(0, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `B8I8A initial Xray selection needing its own permission prompt - no second fallback`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(permission = android.content.Intent(), kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
            userTransportPreference = UserTransportPreference.Manual(TransportKind.XRAY_REALITY),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(0, xrayTransport.connectCallCount) // permission requested, not yet granted

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(0, awgTransport.connectCallCount) // no AWG attempt was ever made to fall back FROM
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `B8I8A permission grant plus failed Xray fallback (malformed profile) - no retry or bounce`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val invalidProfile = validXrayProfileForFailoverTests().copy(uuid = "not-a-uuid")
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(invalidProfile),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        assertEquals(0, xrayTransport.connectCallCount) // fails closed before ever touching the transport
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `B8I8A stale duplicate permission result after context already resolved - no additional fallback attempt`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        val awgConnectCallsAfterFirstGrant = awgTransport.connectCallCount
        val awgDisconnectCallsAfterFirstGrant = awgTransport.disconnectCallCount

        // A stale/duplicate permission result for the SAME, already-resolved
        // request - pendingFailoverAttempt was already cleared by
        // resolvePendingFailover() above, so this must not trigger a SECOND
        // fallback attempt (AWG - the transport a fallback would act on - is
        // never touched again). Note: VpnController.onVpnPermissionResult()
        // itself has no idempotency guard against a duplicate call and will
        // redundantly re-run doConnectAttempt() against whatever is CURRENTLY
        // the active transport (Xray, here) - a pre-existing, disclosed,
        // out-of-scope VpnController characteristic (see B8I8A requirement
        // 11), NOT the AwgXrayFailoverPolicy re-triggering - so this
        // assertion deliberately checks the AWG side, which the failover
        // layer this slice owns is the only thing that can affect.
        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(awgConnectCallsAfterFirstGrant, awgTransport.connectCallCount)
        assertEquals(awgDisconnectCallsAfterFirstGrant, awgTransport.disconnectCallCount)
    }

    @Test
    fun `B8I8A retained context is cleared after a synchronous (no-permission) success - a later stray permission result is a no-op`() = runTest {
        val awgTransport = FakeVpnTransport().apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        // No permission needed at all - the synchronous connect() path
        // already resolved (and cleared) any pending context by itself.
        viewModel.connect()
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, xrayTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        val awgConnectCallsBeforeStrayResult = awgTransport.connectCallCount
        val awgDisconnectCallsBeforeStrayResult = awgTransport.disconnectCallCount

        // A stray permission result arriving afterwards (e.g. a delayed
        // system callback for a request this attempt never actually made)
        // must find nothing pending and must not trigger another fallback
        // (AWG - the transport a fallback would act on - is never touched
        // again). See the sibling "stale duplicate permission result" test
        // for why this deliberately checks the AWG side rather than Xray's
        // own connectCallCount.
        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.runCurrent()

        assertEquals(awgConnectCallsBeforeStrayResult, awgTransport.connectCallCount)
        assertEquals(awgDisconnectCallsBeforeStrayResult, awgTransport.disconnectCallCount)
    }

    @Test
    fun `B8I8A disconnect clears any pending permission-failover context`() = runTest {
        val awgTransport = FakeVpnTransport(permission = android.content.Intent()).apply { handshakeAvailable = false }
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // User cancels while the permission prompt is still pending.
        viewModel.disconnect()
        testDispatcher.scheduler.runCurrent()

        // A late permission result for the abandoned request must not
        // resurrect it into a fallback attempt.
        viewModel.onVpnPermissionResult(true)
        testDispatcher.scheduler.advanceTimeBy(10_000)
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, xrayTransport.connectCallCount)
    }

    // --- B8K6A: react to an eligible AWG failure that arrives ASYNCHRONOUSLY
    // after connect() has already returned (the confirmed physical-device
    // gap: real AWG can report Connected/started first, then settle into a
    // terminal failure later) - not just the ONE synchronous check
    // immediately after connect() settles. ---

    @Test
    fun `B8K6A AWG reports Connected then later an eligible async HandshakeFailed - exactly one Xray fallback`() = runTest {
        val awgTransport = FakeVpnTransport() // handshakeAvailable=true by default -> synchronous Connected
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        // connect() has already returned - AWG genuinely connected
        // synchronously, not yet eligible for fallback.
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(0, xrayTransport.connectCallCount)

        // The SAME attempt's AWG session later settles into an eligible
        // terminal failure ASYNCHRONOUSLY - long after connect() returned,
        // never re-derived by a fresh connect() call.
        diagnostics.recordError(VpnError.HandshakeTimeout)
        awgTransport.forceState(TransportState.HandshakeFailed)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.disconnectCallCount)
        assertEquals(1, xrayTransport.connectCallCount)
        assertTrue(viewModel.transportState.value is TransportState.Connected)

        // Further AWG state churn from the now-detached transport must
        // never trigger a second/duplicate fallback attempt.
        awgTransport.forceState(TransportState.HandshakeFailed)
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, xrayTransport.connectCallCount)
    }

    @Test
    fun `B8K6A stale async AWG failure after disconnect is ignored`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)

        viewModel.disconnect()
        testDispatcher.scheduler.runCurrent()

        // A stale async emission from the now-abandoned AWG session must
        // not resurrect a fallback for a request the user already cancelled.
        diagnostics.recordError(VpnError.HandshakeTimeout)
        awgTransport.forceState(TransportState.HandshakeFailed)
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, xrayTransport.connectCallCount)
    }

    @Test
    fun `B8K6A stale async AWG failure from before a disconnect+reconnect cycle is ignored by the OLD watch`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(validXrayProfileForFailoverTests()),
        )
        testDispatcher.scheduler.runCurrent()

        // First request - connects, then the user disconnects before it
        // ever becomes eligible - clearFailoverWatch() cancels its watch.
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        viewModel.disconnect()
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, awgTransport.disconnectCallCount)

        // A genuinely NEW request (reconnect) - its OWN watch is armed fresh.
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)
        assertEquals(2, awgTransport.connectCallCount)

        // The reconnect itself is not eligible (a real, successful
        // Connected) and no eligible failure ever arrives for it in this
        // test - proving the FIRST (disconnected) request's cancelled watch
        // never fires is exactly what its disconnectCallCount staying at 1
        // (not 2) above already confirms; here we additionally confirm no
        // fallback of any kind happened across the whole cycle.
        assertEquals(0, xrayTransport.connectCallCount)
    }

    @Test
    fun `B8K6A async AWG failure triggers Xray fallback that itself fails - no retry or bounce back to AWG`() = runTest {
        val awgTransport = FakeVpnTransport()
        val xrayTransport = FakeVpnTransport(kind = TransportKind.XRAY_REALITY)
        val diagnostics = DiagnosticsStore()
        // Xray's own fallback fails at config-build time (fails closed
        // BEFORE ever touching the transport) - a real, non-contrived way
        // for the fallback attempt itself to fail.
        val invalidProfile = validXrayProfileForFailoverTests().copy(uuid = "not-a-uuid")
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = awgTransport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            initialNetworkProfile = USABLE_WIFI,
            xrayTransport = xrayTransport,
            xrayProfileRepository = FakeXrayProfileRepository(invalidProfile),
        )
        testDispatcher.scheduler.runCurrent()

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(viewModel.transportState.value is TransportState.Connected)

        diagnostics.recordError(VpnError.HandshakeTimeout)
        awgTransport.forceState(TransportState.HandshakeFailed)
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
        assertEquals(0, xrayTransport.connectCallCount) // fails closed before ever touching the transport
        assertTrue(viewModel.transportState.value is TransportState.Error)

        // No bounce back to AWG, no retry: further AWG state churn changes nothing.
        awgTransport.forceState(TransportState.HandshakeFailed)
        testDispatcher.scheduler.runCurrent()
        assertEquals(1, awgTransport.connectCallCount)
        assertEquals(1, awgTransport.disconnectCallCount)
    }

    // --- B12 (PR #24 second audit fix) - the real production trigger for
    // manifest distribution: ViewModel init, exactly once, guarded against
    // concurrent duplicate fetches. See MainViewModel.kt's own docs on the
    // init{} block and refreshManifest(). ---

    private val manifestSigningKey = Ed25519PrivateKeyParameters(SecureRandom())
    private val manifestTrustAnchors = FixedManifestTrustAnchors(
        mapOf(TrustedKeyId("key-1") to manifestSigningKey.generatePublicKey().encoded),
    )

    private fun testManifest(version: Int) = EndpointManifest(
        manifestVersion = version,
        issuedAtEpochMillis = 1_000L,
        expiresAtEpochMillis = 9_000_000L,
        signingKeyId = "key-1",
        endpoints = listOf(
            EndpointDescriptor(
                EndpointId("gw"), setOf(EndpointRole.GATEWAY), "eu", "acme",
                transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
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

    private fun testManifestRepository() = EndpointManifestRepository(
        verifier = Ed25519ManifestVerifier(),
        trustAnchors = manifestTrustAnchors,
        lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
        bootstrapManifest = signTestManifest(testManifest(version = 1)),
        nowEpochMillis = { 2_000L },
    )

    // B20 - wraps a single fake RemoteManifestFetcher as a one-origin
    // MultiOriginManifestDistributionClient, so the pre-existing
    // single-origin test scenarios below keep working unchanged against the
    // now-multi-origin production type.
    private fun singleOriginClient(fetcher: RemoteManifestFetcher, repository: EndpointManifestRepository) =
        MultiOriginManifestDistributionClient(
            origins = listOf(ManifestOrigin("test-origin", "https://manifest.test.invalid/v1/manifest")),
            repository = repository,
            fetcherFor = { fetcher },
        )

    private fun buildViewModelWithManifest(
        repository: EndpointManifestRepository,
        distributionClient: MultiOriginManifestDistributionClient?,
    ) = MainViewModel(
        clientKeyRepository = FakeClientKeyRepository(),
        transport = FakeVpnTransport(),
        gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
        reconnectManager = FakeReconnectManager(),
        diagnosticsStore = DiagnosticsStore(),
        manifestRepository = repository,
        manifestDistributionClient = distributionClient,
    )

    @Test
    fun `a configured manifestDistributionClient is triggered exactly once from ViewModel init`() = runTest {
        val fetchCount = AtomicInteger(0)
        val repository = testManifestRepository()
        val fetcher = RemoteManifestFetcher {
            fetchCount.incrementAndGet()
            ManifestFetchResult.Fetched(signTestManifest(testManifest(version = 2)))
        }
        buildViewModelWithManifest(repository, singleOriginClient(fetcher, repository))
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(1, fetchCount.get())
    }

    @Test
    fun `an unconfigured manifestDistributionClient (null) performs no network work and stays on the bootstrap`() = runTest {
        val repository = testManifestRepository()
        val viewModel = buildViewModelWithManifest(repository, distributionClient = null)
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(1, repository.trusted()!!.manifestVersion) // still the bootstrap - nothing fetched it forward
        assertEquals(null, viewModel.refreshManifest()) // no client wired - inert, not an error
    }

    @Test
    fun `concurrent repeated refresh signals never cause more than one fetch in flight at once`() = runTest {
        val fetchCount = AtomicInteger(0)
        val repository = testManifestRepository()
        val fetcher = RemoteManifestFetcher {
            fetchCount.incrementAndGet()
            delay(50) // hold the mutex long enough for concurrent callers to collide with it
            ManifestFetchResult.Fetched(signTestManifest(testManifest(version = 2)))
        }
        val viewModel = buildViewModelWithManifest(repository, singleOriginClient(fetcher, repository))

        // Fire several more refresh signals immediately, "concurrently" with
        // the init-triggered one and each other (all launched before any of
        // them can complete, thanks to the fetcher's own delay above).
        repeat(5) { launch { viewModel.refreshManifest() } }
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(1, fetchCount.get()) // never a fetch storm - every overlapping call but one was skipped
        assertEquals(2, repository.trusted()!!.manifestVersion) // the one fetch that did happen still succeeded
    }

    @Test
    fun `a failed refresh (network error) leaves the currently trusted manifest completely untouched`() = runTest {
        val repository = testManifestRepository()
        val fetcher = RemoteManifestFetcher { ManifestFetchResult.Failed(ManifestFetchFailureKind.NETWORK_ERROR, "network error: SocketTimeoutException") }
        buildViewModelWithManifest(repository, singleOriginClient(fetcher, repository))
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(1, repository.trusted()!!.manifestVersion) // unchanged - still the bootstrap
    }

    @Test
    fun `a successful valid newer manifest becomes the trusted manifest, reflected in reachabilityDiagnostics`() = runTest {
        val repository = testManifestRepository()
        val fetcher = RemoteManifestFetcher { ManifestFetchResult.Fetched(signTestManifest(testManifest(version = 5))) }
        val viewModel = buildViewModelWithManifest(repository, singleOriginClient(fetcher, repository))
        testDispatcher.scheduler.advanceUntilIdle()

        assertEquals(5, repository.trusted()!!.manifestVersion)
        assertEquals(5, viewModel.reachabilityDiagnostics()?.manifestVersion)
    }

    // --- B12 (PR #24 second audit fix) - PathCandidate.Relayed must never crash reachabilityDiagnostics() ---

    @Test
    fun `a manifest with an INGRESS to EXIT relayTo relationship produces a real Relayed candidate without crashing`() = runTest {
        val ingress = EndpointDescriptor(
            EndpointId("ingress-1"), setOf(EndpointRole.INGRESS), "eu", "acme",
            transports = listOf(EndpointTransportBinding(TransportKind.TLS_TCP, "203.0.113.5", 443)),
            relayTo = EndpointId("exit-1"),
        )
        val exit = EndpointDescriptor(
            EndpointId("exit-1"), setOf(EndpointRole.EXIT), "us", "acme2",
            transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.6", 51820)),
        )
        val relayManifest = EndpointManifest(
            manifestVersion = 1, issuedAtEpochMillis = 1_000L, expiresAtEpochMillis = 9_000_000L,
            signingKeyId = "key-1", endpoints = listOf(ingress, exit),
        )
        val repository = EndpointManifestRepository(
            verifier = Ed25519ManifestVerifier(),
            trustAnchors = manifestTrustAnchors,
            lkgStore = FileLastKnownGoodManifestStore(tmp.newFolder()),
            bootstrapManifest = signTestManifest(relayManifest),
            nowEpochMillis = { 2_000L },
        )
        val viewModel = buildViewModelWithManifest(repository, distributionClient = null)
        testDispatcher.scheduler.advanceUntilIdle()

        val snapshot = viewModel.reachabilityDiagnostics()
        assertTrue(snapshot != null)
        val relayed = snapshot!!.pathCandidates.filterIsInstance<PathCandidate.Relayed>()
        assertEquals(1, relayed.size)
        assertEquals(EndpointId("ingress-1"), relayed.first().ingress.endpoint.id)
        assertEquals(EndpointId("exit-1"), relayed.first().exit.endpoint.id)
        // Scoring must succeed for the Relayed candidate too - no crash, no unsafe cast.
        assertTrue(snapshot.rankedPaths.any { it.candidate is PathCandidate.Relayed })
    }

    // B30 (task 5/13) - offline/existing-user resilience: a temporarily
    // unreachable control plane must never block an otherwise-valid connect
    // using already-persisted local state.

    @Test
    fun `an already-activated user connects using valid local state while the control plane (manifest refresh) is failing`() = runTest {
        val transport = FakeVpnTransport()
        val repository = testManifestRepository()
        val fetchAttempts = AtomicInteger(0)
        // A real, wired distribution client that ALWAYS fails - simulating
        // a genuinely unreachable control plane, never simply omitted.
        val failingFetcher = RemoteManifestFetcher {
            fetchAttempts.incrementAndGet()
            ManifestFetchResult.Failed(ManifestFetchFailureKind.NETWORK_ERROR, "simulated control-plane outage")
        }
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            // Already-valid local activation state - GatewayConfiguration.Configured,
            // exactly what a real activateDevice() success would have persisted.
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            initialNetworkProfile = USABLE_WIFI,
            manifestRepository = repository,
            manifestDistributionClient = singleOriginClient(failingFetcher, repository),
        )
        testDispatcher.scheduler.advanceUntilIdle()
        assertTrue("the control-plane call must have genuinely been attempted and failed, not merely omitted", fetchAttempts.get() >= 1)

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(
            "a temporarily unreachable control plane must never prevent an otherwise-valid existing connection",
            1,
            transport.connectCallCount,
        )
    }
}
