@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
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
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The VPN session has ONE owner per main process: every MainActivity takes
 * its MainViewModel (and so its VpnController and transports) from
 * [NovaVpnApplication.viewModelStore] via [MainActivity.sessionViewModel],
 * never from its own store. Field evidence (2026-10-27, OPPO): a second
 * MainActivity started by an explicit intent showed Disconnected over a
 * running AWG tunnel because it had built its own controller.
 *
 * These are JVM tests with a fake transport on a bare NovaVpnApplication
 * instance (its onCreate is not run): they prove ownership and the state every
 * Activity reads, not on-screen rendering or a real tunnel.
 */
class SessionViewModelOwnerTest {

    private val testDispatcher = StandardTestDispatcher()
    private val app = NovaVpnApplication()
    private val transport = FakeVpnTransport()
    private val reconnectManager = FakeReconnectManager()
    private var created = 0

    /** Stands in for MainViewModel.Factory: same ViewModel class, fake dependencies, counts constructions. */
    private val factory = object : ViewModelProvider.Factory {
        @Suppress("UNCHECKED_CAST")
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            created++
            return MainViewModel(
                clientKeyRepository = FakeClientKeyRepository(),
                transport = transport,
                gatewayConfigurationRepository = FakeGatewayConfigurationRepository(CONFIGURED_GATEWAY),
                reconnectManager = reconnectManager,
                diagnosticsStore = DiagnosticsStore(),
                initialNetworkProfile = USABLE_WIFI,
            ) as T
        }
    }

    /** What one MainActivity.onCreate does. */
    private fun activityViewModel(): MainViewModel = MainActivity.sessionViewModel(app, app, factory)

    @Before
    fun setUp() {
        Dispatchers.setMain(testDispatcher)
    }

    @After
    fun tearDown() {
        app.viewModelStore.clear()
        Dispatchers.resetMain()
    }

    private fun connectedSession(): MainViewModel {
        val first = activityViewModel()
        testDispatcher.scheduler.runCurrent()
        first.connect()
        testDispatcher.scheduler.runCurrent()
        assertTrue(first.transportState.value is TransportState.Connected)
        return first
    }

    @Test
    fun `two MainActivity instances share one MainViewModel and one VpnController`() {
        val first = activityViewModel()
        val second = activityViewModel()

        assertSame(first, second)
        // transportState IS VpnController.state - one StateFlow means one controller.
        assertSame(first.transportState, second.transportState)
        assertEquals(1, created)
    }

    @Test
    fun `an Activity created during an active session reads Connected, never a fresh Disconnected`() = runTest {
        connectedSession()

        val second = activityViewModel()

        assertTrue(second.transportState.value is TransportState.Connected)
    }

    @Test
    fun `repeated explicit launches never start a second session or a second controller`() = runTest {
        connectedSession()

        repeat(5) { activityViewModel() }
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, created)
        assertEquals(1, transport.connectCallCount)
        assertEquals(1, reconnectManager.startCallCount)
    }

    @Test
    fun `finishing an Activity and starting a new one keeps the session and its state`() = runTest {
        val first = connectedSession()
        // Finishing an Activity clears only that Activity's own store, which
        // no longer holds the session - the next Activity asks the app store.
        val next = activityViewModel()

        assertSame(first, next)
        assertTrue(next.transportState.value is TransportState.Connected)
        assertEquals("the controller was never shut down", 0, reconnectManager.stopCallCount)
        assertEquals(0, transport.disconnectCallCount)
    }

    @Test
    fun `a normal disconnect from any Activity updates the shared state for all of them`() = runTest {
        val first = connectedSession()
        val second = activityViewModel()

        second.disconnect()
        testDispatcher.scheduler.runCurrent()

        assertEquals(1, transport.disconnectCallCount)
        assertEquals(TransportState.Disconnected, first.transportState.value)
        assertEquals(TransportState.Disconnected, second.transportState.value)
    }

    @Test
    fun `the old per-Activity owner is what produced a second Disconnected controller`() = runTest {
        connectedSession()
        // The pre-fix wiring: each Activity was its own ViewModelStoreOwner.
        val activityOwner = object : ViewModelStoreOwner {
            override val viewModelStore = ViewModelStore()
        }

        val perActivity = MainActivity.sessionViewModel(activityOwner, app, factory)

        assertNotSame(activityViewModel(), perActivity)
        assertEquals(TransportState.Disconnected, perActivity.transportState.value)
        activityOwner.viewModelStore.clear()
    }

    private companion object {
        val USABLE_WIFI = net.pocvpn.client.network.NetworkProfile(
            type = net.pocvpn.client.network.NetworkType.WIFI, validatedInternet = true, metered = false,
            roaming = false, captivePortal = false, ipv4Available = true, ipv6Available = false,
            vpnActive = false, generation = 1,
        )

        val CONFIGURED_GATEWAY = GatewayConfiguration.Configured(
            endpointHost = "203.0.113.10", endpointPort = 51820,
            serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
            clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1",
            allowedIps = listOf("0.0.0.0/0", "::/0"), profile = AwgProfile.none(),
        )
    }
}
