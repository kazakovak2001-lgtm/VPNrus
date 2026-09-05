package net.pocvpn.client.bootstrap

import android.content.Intent
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.VpnTransport
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.config.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A fake bootstrap [VpnTransport] whose connect()/handshake behavior is fully scripted for tests. */
private class ScriptedBootstrapTransport(
    private val shouldConnect: Boolean,
    private val handshakeEpochMillis: Long? = null,
) : VpnTransport {
    override val name: String = "scripted-bootstrap"
    override val kind: TransportKind = TransportKind.AMNEZIA_WG
    override val capabilities: TransportCapabilities = TransportCapabilities.amneziaWg()
    private val stateFlow = MutableStateFlow<TransportState>(TransportState.Disconnected)
    var connectCalled = false
        private set
    var disconnectCalled = false
        private set

    override fun preparePermissionIntent(): Intent? = null

    override suspend fun connect(config: TransportConfig) {
        connectCalled = true
        if (!shouldConnect) throw RuntimeException("simulated bootstrap connect failure")
        stateFlow.value = TransportState.Connected
    }

    override suspend fun disconnect() {
        disconnectCalled = true
        stateFlow.value = TransportState.Disconnected
    }

    override fun observeState(): Flow<TransportState> = stateFlow

    override suspend fun stats(): TransportStats =
        if (handshakeEpochMillis != null) {
            TransportStats.Counters(bytesReceived = 0, bytesSent = 0, lastHandshakeEpochMillis = handshakeEpochMillis)
        } else {
            TransportStats.Unavailable
        }
}

class BootstrapTunnelControllerTest {

    // Test A (tunnel-controller half) - Frankfurt succeeds on the first try.
    @Test
    fun `germany candidate connecting immediately is reported Connected, Stockholm never attempted`() = runTest {
        val germanyTransport = ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = 1_000L)
        var stockholmBuilt = false
        val controller = BootstrapTunnelController(
            transportFactory = { candidate ->
                when (candidate) {
                    ProductionGatewayId.GERMANY -> germanyTransport
                    ProductionGatewayId.STOCKHOLM -> {
                        stockholmBuilt = true
                        ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = 1_000L)
                    }
                }
            },
            nowProvider = { 0L },
            delayMs = { },
        )

        val result = controller.connect()

        assertEquals(BootstrapState.Connected(ProductionGatewayId.GERMANY), result)
        assertTrue(germanyTransport.connectCalled)
        assertTrue("Stockholm must never be attempted once Germany already succeeded", !stockholmBuilt)
    }

    // Test B - Frankfurt fails, Stockholm succeeds.
    @Test
    fun `germany bootstrap failure falls back to stockholm, which succeeds`() = runTest {
        val germanyTransport = ScriptedBootstrapTransport(shouldConnect = false)
        val stockholmTransport = ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = 5_000L)
        val controller = BootstrapTunnelController(
            transportFactory = { candidate ->
                when (candidate) {
                    ProductionGatewayId.GERMANY -> germanyTransport
                    ProductionGatewayId.STOCKHOLM -> stockholmTransport
                }
            },
            nowProvider = { 0L },
            delayMs = { },
        )

        val result = controller.connect()

        assertEquals(BootstrapState.Connected(ProductionGatewayId.STOCKHOLM), result)
        assertTrue(germanyTransport.connectCalled)
        assertTrue(stockholmTransport.connectCalled)
    }

    // Test C - both candidates fail -> Unavailable, never loops past the known set.
    @Test
    fun `both candidates failing yields Unavailable listing exactly the two known candidates, no retry loop`() = runTest {
        var germanyAttempts = 0
        var stockholmAttempts = 0
        val controller = BootstrapTunnelController(
            transportFactory = { candidate ->
                when (candidate) {
                    ProductionGatewayId.GERMANY -> { germanyAttempts++; ScriptedBootstrapTransport(shouldConnect = false) }
                    ProductionGatewayId.STOCKHOLM -> { stockholmAttempts++; ScriptedBootstrapTransport(shouldConnect = false) }
                }
            },
            nowProvider = { 0L },
            delayMs = { },
        )

        val result = controller.connect()

        assertEquals(BootstrapState.Unavailable(listOf(ProductionGatewayId.GERMANY, ProductionGatewayId.STOCKHOLM)), result)
        assertEquals(1, germanyAttempts)
        assertEquals(1, stockholmAttempts)
    }

    // Test I - teardown fully completes (transport.disconnect() observed, state back to Idle) before this call returns.
    @Test
    fun `teardown disconnects the active transport and returns to Idle before returning`() = runTest {
        val germanyTransport = ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = 1_000L)
        val controller = BootstrapTunnelController(
            transportFactory = { germanyTransport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 0L },
            delayMs = { },
        )
        val connected = controller.connect()
        assertTrue(connected is BootstrapState.Connected)

        controller.teardown()

        assertTrue("disconnect() must have been called on the real active transport", germanyTransport.disconnectCalled)
        assertEquals(BootstrapState.Idle, controller.state.value)
    }

    // A stale/never-usable handshake never counts as Connected - proves
    // awaitUsableHandshake genuinely requires freshness, not merely
    // TransportState.Connected/interface-up (matches
    // VpnController.awaitFreshHandshake's own distinction).
    @Test
    fun `a transport that connects but never reports a fresh handshake is treated as a failed candidate`() = runTest {
        val staleHandshakeTransport = ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = -1L)
        val controller = BootstrapTunnelController(
            transportFactory = { staleHandshakeTransport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 10_000L },
            delayMs = { },
        )

        val result = controller.connect()

        assertEquals(BootstrapState.Unavailable(listOf(ProductionGatewayId.GERMANY)), result)
        assertTrue("a candidate that never becomes usable must still be torn down before moving on", staleHandshakeTransport.disconnectCalled)
    }

    @Test
    fun `a second connect call while already connected is refused, never a concurrent second sequence`() = runTest {
        val germanyTransport = ScriptedBootstrapTransport(shouldConnect = true, handshakeEpochMillis = 1_000L)
        val controller = BootstrapTunnelController(
            transportFactory = { germanyTransport },
            candidates = listOf(ProductionGatewayId.GERMANY),
            nowProvider = { 0L },
            delayMs = { },
        )
        val first = controller.connect()
        val second = controller.connect()

        assertEquals(first, second)
        assertEquals(BootstrapState.Connected(ProductionGatewayId.GERMANY), second)
    }
}
