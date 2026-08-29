@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.provisioning.ProvisioningResult
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
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
}
