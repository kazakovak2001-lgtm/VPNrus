@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.provisioning.XrayProfileProvisioner
import net.pocvpn.client.provisioning.XrayProfileProvisioningOutcome
import net.pocvpn.client.provisioning.XrayProfileResult
import net.pocvpn.client.provisioning.toXrayProfile
import net.pocvpn.client.smartconnect.ConnectionScoreReason
import net.pocvpn.client.smartconnect.ProductionGateway
import net.pocvpn.client.smartconnect.SmartConnectDecision
import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportOrchestrator
import net.pocvpn.client.transport.TransportStatus
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
}
