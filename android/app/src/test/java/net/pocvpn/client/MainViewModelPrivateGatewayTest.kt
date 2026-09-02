@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.FileGatewaySelectionModeStore
import net.pocvpn.client.vpn.config.FilePrivateGatewayStore
import net.pocvpn.client.vpn.config.FileSelectedGatewayStore
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.config.PrivateGatewayConfig
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * B22 - the MainViewModel-level facets of the required test list: PRIVATE
 * resolves ONLY from PrivateGatewayStore (item 3), never touches
 * ProductionGatewayCatalog/manifest logic (item 4 - proven here by the
 * managed gatewayConfigurationRepository fake never being consulted), a
 * missing local client identity fails closed (item 6), and switching away
 * from PRIVATE never mutates/deletes managed gateway state (item 9). Items
 * 1/2 (AUTO/MANUAL_MANAGED unchanged) are proven by the pre-existing
 * MainViewModelTest suite passing untouched - no new tests duplicate that.
 */
class MainViewModelPrivateGatewayTest {

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

    private val validPrivateConfig = PrivateGatewayConfig(
        host = "203.0.113.5",
        port = 51820,
        serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
        clientTunnelIp = "10.13.13.2",
        gatewayTunnelIp = "10.13.13.1",
        awgProfile = AwgProfile(
            initPacketMagicHeader = "1106684696",
            responsePacketMagicHeader = "3677857287",
            underloadPacketMagicHeader = "353316806",
            transportPacketMagicHeader = "2068198996",
        ),
    )

    private fun freshDir() = tmp.newFolder()

    @Test
    fun `PRIVATE mode connects using only PrivateGatewayStore, never consulting the managed gatewayConfigurationRepository`() = runTest {
        val privateGatewayStore = FilePrivateGatewayStore(freshDir())
        privateGatewayStore.write(validPrivateConfig)
        val managedConfigRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing)
        val transport = FakeVpnTransport()
        val gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir())
        gatewaySelectionModeStore.write(GatewaySelectionMode.PRIVATE)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(privateKey = "MANAGED_KEY=="),
            transport = transport,
            gatewayConfigurationRepository = managedConfigRepository,
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = gatewaySelectionModeStore,
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
        )

        assertEquals(GatewaySelectionMode.PRIVATE, viewModel.gatewaySelectionMode.value)
        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.connectCallCount)
        // Item 4: the managed/catalog/manifest-facing repository is never touched by a PRIVATE attempt.
        assertEquals(0, managedConfigRepository.getCallCount)
        val awgConfig = (transport.lastConfig as TransportConfig.Awg).config
        assertEquals("PRIVATE_KEY==", awgConfig.privateKeyBase64)
        assertEquals("203.0.113.5", awgConfig.peer.endpointHost)
    }

    @Test
    fun `PRIVATE mode with no saved config fails closed and never connects`() = runTest {
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir())
        gatewaySelectionModeStore.write(GatewaySelectionMode.PRIVATE)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            gatewaySelectionModeStore = gatewaySelectionModeStore,
            privateGatewayStore = FilePrivateGatewayStore(freshDir()),
            privateGatewayKeyRepository = FakeClientKeyRepository(),
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertEquals(VpnError.GatewayConfigurationMissing, diagnostics.snapshot.value.lastError)
        assertTrue(viewModel.transportState.value is TransportState.Error)
    }

    @Test
    fun `PRIVATE mode with no local client identity wired fails closed - never falls back to the managed identity`() = runTest {
        val privateGatewayStore = FilePrivateGatewayStore(freshDir())
        privateGatewayStore.write(validPrivateConfig)
        val transport = FakeVpnTransport()
        val diagnostics = DiagnosticsStore()
        val gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir())
        gatewaySelectionModeStore.write(GatewaySelectionMode.PRIVATE)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(privateKey = "MANAGED_KEY=="),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = diagnostics,
            gatewaySelectionModeStore = gatewaySelectionModeStore,
            privateGatewayStore = privateGatewayStore,
            // privateGatewayKeyRepository intentionally left null (default) -
            // simulates a build/config with no local identity wired.
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(0, transport.connectCallCount)
        assertEquals(VpnError.GatewayConfigurationMissing, diagnostics.snapshot.value.lastError)
    }

    @Test
    fun `switching gatewaySelectionMode to PRIVATE and back never mutates the managed SelectedGatewayStore or ClientTunnelIdentityStore`() = runTest {
        val selectedGatewayDir = freshDir()
        val identityDir = freshDir()
        val selectedGatewayStore = FileSelectedGatewayStore(selectedGatewayDir)
        selectedGatewayStore.write(ProductionGatewayId.STOCKHOLM)
        val clientTunnelIdentityStore = FileClientTunnelIdentityStore(identityDir)
        clientTunnelIdentityStore.write(ProductionGatewayId.STOCKHOLM, "10.77.0.9")

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = selectedGatewayStore,
            clientTunnelIdentityStore = clientTunnelIdentityStore,
            gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir()),
            privateGatewayStore = FilePrivateGatewayStore(freshDir()),
            privateGatewayKeyRepository = FakeClientKeyRepository(),
        )

        viewModel.selectGatewaySelectionMode(GatewaySelectionMode.PRIVATE)
        viewModel.selectGatewaySelectionMode(GatewaySelectionMode.MANUAL_MANAGED)
        testDispatcher.scheduler.runCurrent()

        assertEquals(ProductionGatewayId.STOCKHOLM, selectedGatewayStore.read())
        assertEquals("10.77.0.9", clientTunnelIdentityStore.read(ProductionGatewayId.STOCKHOLM))
    }

    @Test
    fun `removePrivateGatewayConfig only clears the private store - never touches managed gateway state`() = runTest {
        val privateGatewayStore = FilePrivateGatewayStore(freshDir())
        privateGatewayStore.write(validPrivateConfig)
        val selectedGatewayStore = FileSelectedGatewayStore(freshDir())
        selectedGatewayStore.write(ProductionGatewayId.GERMANY)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            selectedGatewayStore = selectedGatewayStore,
            gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir()),
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(),
        )

        viewModel.removePrivateGatewayConfig()

        assertNull(privateGatewayStore.read())
        assertEquals(ProductionGatewayId.GERMANY, selectedGatewayStore.read())
    }

    @Test
    fun `savePrivateGatewayConfig rejects a malformed config and never persists it`() = runTest {
        val privateGatewayStore = FilePrivateGatewayStore(freshDir())
        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir()),
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(),
        )

        val result = viewModel.savePrivateGatewayConfig(
            host = "203.0.113.5",
            port = 99999,
            serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
            clientTunnelIp = "10.13.13.2",
            gatewayTunnelIp = "10.13.13.1",
            awgProfile = validPrivateConfig.awgProfile,
        )

        assertTrue(result is net.pocvpn.client.vpn.config.PrivateGatewayValidationResult.Invalid)
        assertNull(privateGatewayStore.read())
    }
}
