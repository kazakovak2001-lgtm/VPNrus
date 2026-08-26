@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.vpn.FakeClientKeyRepository
import net.pocvpn.client.vpn.FakeGatewayConfigurationRepository
import net.pocvpn.client.vpn.FakeReconnectManager
import net.pocvpn.client.vpn.FakeVpnTransport
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class MainViewModelTest {

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
}
