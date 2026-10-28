@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.diagnostics.VpnError
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.InMemoryDiagnosticSessionStore
import net.pocvpn.client.diagnostics.support.SupportDiagnosticsRecorder
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.blocksGatewaySelection
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.FileClientTunnelIdentityStore
import net.pocvpn.client.vpn.config.FileGatewayAutoModeStore
import net.pocvpn.client.vpn.config.FileGatewaySelectionModeStore
import net.pocvpn.client.vpn.config.FilePrivateGatewayStore
import net.pocvpn.client.vpn.config.FileSelectedGatewayStore
import net.pocvpn.client.vpn.config.GatewayAutoModeStore
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
        val supportStore = InMemoryDiagnosticSessionStore()
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
            supportDiagnosticsRecorder = SupportDiagnosticsRecorder(supportStore, "1.0", 1L),
            supportDiagnosticsStore = supportStore,
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
        val events = supportStore.recent().single().events
        val candidate = events.single { it.type == DiagnosticEventType.CANDIDATE_ATTEMPT_STARTED }
        assertEquals(PrivateGatewayConfig.ID, candidate.tags["plannedEndpointId"])
        assertTrue(!candidate.tags.containsKey("attemptedEndpointId"))
        for (type in listOf(DiagnosticEventType.TRANSPORT_START, DiagnosticEventType.PATH_SUCCEEDED, DiagnosticEventType.VPN_PROTECTED)) {
            val event = events.single { it.type == type }
            assertEquals(PrivateGatewayConfig.ID, event.tags["attemptedEndpointId"])
            assertEquals("1", event.tags["attemptOrdinal"])
        }
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

    private fun assertBlocksGatewaySelection(state: TransportState) {
        assertTrue("Expected blocksGatewaySelection=true", state.blocksGatewaySelection())
    }

    // In-memory mode store so we can assert on writes while File-backed
    // counterparts persist across reconstruction (see the next test).
    private fun writableModeStore(initial: GatewaySelectionMode) =
        object : net.pocvpn.client.vpn.config.GatewaySelectionModeStore {
            var current: GatewaySelectionMode = initial
                private set
            var writeCallCount = 0
                private set
            override fun read() = current
            override fun write(mode: GatewaySelectionMode) {
                writeCallCount++
                current = mode
            }
        }

    @Test
    fun `switching from PRIVATE to AUTO persists the new mode and restores it on reconstruction`() = runTest {
        val dir = freshDir()
        val privateGatewayStore = FilePrivateGatewayStore(dir)
        privateGatewayStore.write(validPrivateConfig)
        // gatewayAutoModeStore initialized to false (Manual) - simulates post-B22
        // legacy store state where a newly constructed ViewModel must discover the
        // current mode from gatewaySelectionModeStore, not from the auto-mode flag.
        val autoStore = FileGatewayAutoModeStore(dir)
        val modeStore = writableModeStore(GatewaySelectionMode.PRIVATE)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = modeStore,
            gatewayAutoModeStore = autoStore,
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
        )

        assertEquals(GatewaySelectionMode.PRIVATE, viewModel.gatewaySelectionMode.value)
        // selectGatewaySelectionMode is a plain (non-suspend) function; the
        // internal write chain completes synchronously on the calling thread.
        viewModel.selectGatewaySelectionMode(GatewaySelectionMode.AUTO)

        assertEquals(GatewaySelectionMode.AUTO, viewModel.gatewaySelectionMode.value)
        assertTrue(viewModel.gatewayAutoMode.value)
        assertEquals(GatewaySelectionMode.AUTO, modeStore.read())
        assertEquals(1, modeStore.writeCallCount)
        assertTrue(autoStore.read())

        // Restart simulation: a brand-new ViewModel reads the persisted AUTO
        // state from disk, confirming the write was durable.
        val restarted = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(),
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = modeStore,
            gatewayAutoModeStore = autoStore,
            privateGatewayStore = privateGatewayStore,
        )
        assertEquals(GatewaySelectionMode.AUTO, restarted.gatewaySelectionMode.value)
        assertTrue(restarted.gatewayAutoMode.value)
    }

    @Test
    fun `active PRIVATE connection blocks gateway-mode switch until disconnect`() = runTest {
        val privateGatewayStore = FilePrivateGatewayStore(freshDir())
        privateGatewayStore.write(validPrivateConfig)
        val transport = FakeVpnTransport()
        // FileGatewaySelectionModeStore is the production backing store;
        // the test reads back from it to confirm the blocked write had no effect.
        val gatewaySelectionModeStore = FileGatewaySelectionModeStore(freshDir())
        gatewaySelectionModeStore.write(GatewaySelectionMode.PRIVATE)

        val viewModel = MainViewModel(
            clientKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
            transport = transport,
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = gatewaySelectionModeStore,
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
        )

        viewModel.connect()
        testDispatcher.scheduler.runCurrent()

        assertTrue("session must be Connected", viewModel.transportState.value is TransportState.Connected)
        assertBlocksGatewaySelection(viewModel.transportState.value)

        // Attempt to switch to AUTO while Connected - selectGatewaySelectionMode
        // must observe blocksGatewaySelection() and abort without writing.
        viewModel.selectGatewaySelectionMode(GatewaySelectionMode.AUTO)
        // Plain function - nothing deferred to the scheduler.

        assertEquals(GatewaySelectionMode.PRIVATE, viewModel.gatewaySelectionMode.value)
        assertEquals(GatewaySelectionMode.PRIVATE, gatewaySelectionModeStore.read())
        // Transport remains connected - no disconnect induced by the blocked switch.
        assertTrue(viewModel.transportState.value is TransportState.Connected)
    }

    @Test
    fun `PRIVATE → AUTO transition never leaks private key to managed identity`() = runTest {
        val dir = freshDir()
        val privateGatewayStore = FilePrivateGatewayStore(dir)
        privateGatewayStore.write(validPrivateConfig)
        val autoStore = FileGatewayAutoModeStore(dir)
        val modeStore = writableModeStore(GatewaySelectionMode.PRIVATE)
        // The managed key repository has a DIFFERENT key - any write by the
        // PRIVATE→AUTO transition would be observable as a key rotation.
        val managedKeyRepo = FakeClientKeyRepository(privateKey = "MANAGED_PRIVATE_KEY==")

        val viewModel = MainViewModel(
            clientKeyRepository = managedKeyRepo,
            transport = FakeVpnTransport(),
            gatewayConfigurationRepository = FakeGatewayConfigurationRepository(GatewayConfiguration.Missing),
            reconnectManager = FakeReconnectManager(),
            diagnosticsStore = DiagnosticsStore(),
            gatewaySelectionModeStore = modeStore,
            gatewayAutoModeStore = autoStore,
            privateGatewayStore = privateGatewayStore,
            privateGatewayKeyRepository = FakeClientKeyRepository(privateKey = "PRIVATE_KEY=="),
        )

        // Verify both keys are distinct before any mode switch.
        assertEquals("MANAGED_PRIVATE_KEY==", managedKeyRepo.getPrivateKeyForTunnel())

        viewModel.selectGatewaySelectionMode(GatewaySelectionMode.AUTO)
        assertEquals(GatewaySelectionMode.AUTO, viewModel.gatewaySelectionMode.value)
        // Managed key repo was never touched by the mode switch - the private
        // key alias file is an entirely separate store.
        assertEquals("MANAGED_PRIVATE_KEY==", managedKeyRepo.getPrivateKeyForTunnel())
    }
}
