package net.pocvpn.client.vpn

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.diagnostics.DiagnosticsStore
import net.pocvpn.client.identity.ClientIdentity
import net.pocvpn.client.identity.ClientKeyRepository
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfiguration
import net.pocvpn.client.vpn.config.GatewayConfigurationRepository
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B7I item 2: exercises AndroidReconnectManager against the REAL
 * ConnectivityManager on-device, driving network transitions via
 * `adb shell svc wifi/data`. The transport here is a local fake, so this
 * validates the controller's reconnect *orchestration* (state machine,
 * bounded backoff, cancellation) against genuine Android network callbacks -
 * it is NOT a claim of a real AmneziaWG reconnect, which remains UNVERIFIED
 * until a real gateway exists (see B7I report).
 */
@RunWith(AndroidJUnit4::class)
class VpnControllerRealNetworkInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String) {
        instrumentation.uiAutomation.executeShellCommand(cmd).close()
    }

    private fun setNetworkUp(up: Boolean) {
        val state = if (up) "enable" else "disable"
        shell("svc wifi $state")
        shell("svc data $state")
    }

    @Before
    fun ensureNetworkUpBeforeTest() {
        setNetworkUp(true)
        Thread.sleep(1_000)
    }

    @After
    fun restoreNetwork() {
        setNetworkUp(true)
        Thread.sleep(1_000)
    }

    private class FakeTransport : VpnTransport {
        override val name = "fake-instrumented"
        override val kind: TransportKind = TransportKind.AMNEZIA_WG
        override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
        private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
        var connectCallCount = 0
            private set

        override fun preparePermissionIntent(): Intent? = null

        override suspend fun connect(config: TransportConfig) {
            connectCallCount++
            stateFlow.value = TransportState.Connected
        }

        override suspend fun disconnect() {
            stateFlow.value = TransportState.Disconnected
        }

        override fun observeState(): Flow<TransportState> = stateFlow
    }

    private class FakeGatewayConfig : GatewayConfigurationRepository {
        override fun get(): GatewayConfiguration = GatewayConfiguration.Configured(
            endpointHost = "203.0.113.10",
            endpointPort = 51820,
            serverPublicKeyBase64 = "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=",
            clientTunnelIp = "10.77.0.2",
            gatewayTunnelIp = "10.77.0.1",
            allowedIps = listOf("0.0.0.0/0"),
            profile = AwgProfile.none(),
        )
    }

    private class FakeKeyRepo : ClientKeyRepository {
        override suspend fun getOrCreateIdentity() = ClientIdentity("FAKE_PUB_KEY_NOT_REAL===")
        override suspend fun getPublicKey() = "FAKE_PUB_KEY_NOT_REAL==="
        override suspend fun getPrivateKeyForTunnel() = "FAKE_PRIV_KEY_NOT_REAL==="
        override suspend fun clearIdentity() {}
    }

    private fun waitUntil(timeoutMs: Long = 15_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (condition()) return
            Thread.sleep(100)
        }
        throw AssertionError("condition not met within ${timeoutMs}ms; last-seen state check failed")
    }

    @Test
    fun networkLossAndRestore_drivesReconnectStateMachine_thenReconnectsBounded() = runBlocking {
        val scope = CoroutineScope(Dispatchers.Default + Job())
        val transport = FakeTransport()
        val reconnectManager = AndroidReconnectManager(context)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeKeyRepo(), FakeGatewayConfig(), reconnectManager, diagnostics, scope,
        )
        try {
            controller.connect()
            waitUntil { controller.state.value is TransportState.Connected }
            assertEquals(1, transport.connectCallCount)

            setNetworkUp(false)
            waitUntil { controller.state.value is TransportState.Reconnecting }
            assertFalse("real ConnectivityManager must report network unavailable", reconnectManager.isNetworkAvailable())

            // Real network returns; the reconnect loop's next backoff check must
            // pick it up and reconnect exactly once more - bounded, not spun.
            setNetworkUp(true)
            waitUntil(timeoutMs = 20_000) { controller.state.value is TransportState.Connected }
            assertEquals(2, transport.connectCallCount)
        } finally {
            controller.shutdown()
            scope.cancel()
        }
    }

    @Test
    fun userDisconnectDuringReconnect_cancelsReconnect_andNetworkReturnDoesNotReconnect() = runBlocking {
        val scope = CoroutineScope(Dispatchers.Default + Job())
        val transport = FakeTransport()
        val reconnectManager = AndroidReconnectManager(context)
        val diagnostics = DiagnosticsStore()
        val controller = VpnController(
            transport, FakeKeyRepo(), FakeGatewayConfig(), reconnectManager, diagnostics, scope,
        )
        try {
            controller.connect()
            waitUntil { controller.state.value is TransportState.Connected }

            setNetworkUp(false)
            waitUntil { controller.state.value is TransportState.Reconnecting }

            controller.disconnect()
            waitUntil { controller.state.value is TransportState.Disconnected }

            setNetworkUp(true)
            // Give the (should-be-cancelled) reconnect loop ample real time to
            // prove it stays cancelled and does not resurrect a stale job.
            Thread.sleep(5_000)
            assertEquals(TransportState.Disconnected, controller.state.value)
            assertEquals(1, transport.connectCallCount) // only the original connect - no reconnect after user disconnect
        } finally {
            controller.shutdown()
            scope.cancel()
        }
    }
}
