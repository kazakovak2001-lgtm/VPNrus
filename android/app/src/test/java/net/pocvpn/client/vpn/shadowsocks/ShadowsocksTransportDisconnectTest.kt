package net.pocvpn.client.vpn.shadowsocks

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

/**
 * B45B-4P fix - a real ownership/cleanup bug found on a physical device:
 * SHADOWSOCKS_2022 genuinely selected, sslocal started, TUN established, UI
 * reached Protected - but on Disconnect the UI moved to Disconnected while
 * `sslocal`/`tun0` were both still alive (an `am force-stop` was required to
 * actually clean up). Root cause: [ShadowsocksTransport.disconnect] used to
 * skip sending [ShadowsocksVpnService.ACTION_STOP] entirely whenever the
 * transport's last-known state was already [TransportState.Error], wrongly
 * assuming Error always means the service already tore itself down. These
 * tests prove that assumption is gone: every call that isn't already
 * genuinely [TransportState.Disconnected] now deterministically asks the
 * service to stop.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShadowsocksTransportDisconnectTest {

    private val context = ApplicationProvider.getApplicationContext<Application>()

    private fun lastStartedStopIntentCount(): Int {
        val shadowApplication = Shadows.shadowOf(context)
        var count = 0
        while (true) {
            val intent = shadowApplication.nextStartedService ?: break
            if (intent.action == ShadowsocksVpnService.ACTION_STOP) count++
        }
        return count
    }

    @Test
    fun `disconnect from a fresh (Disconnected) transport is a harmless no-op - no stop intent sent`() = runTest {
        val transport = ShadowsocksTransport(context, disconnectConfirmTimeoutMillis = 50L)

        transport.disconnect()

        assertEquals(TransportState.Disconnected, transport.observeState().value())
        assertEquals(0, lastStartedStopIntentCount())
    }

    @Test
    fun `disconnect while state is Error - the exact physical bug - still sends ACTION_STOP, never skips teardown`() = runTest {
        // Drive the transport into Error via its own real public API - no
        // VPN permission is ever granted under Robolectric, so connect()'s
        // own early check reaches TransportState.Error without ever
        // touching the service (see connect()'s own docs).
        val transport = ShadowsocksTransport(context, disconnectConfirmTimeoutMillis = 50L)
        val config = net.pocvpn.client.vpn.config.TransportConfig.Shadowsocks(
            endpointId = net.pocvpn.client.reachability.EndpointId("frankfurt"),
            host = "152.70.43.1",
            port = 28388,
        )
        transport.connect(config)
        assertTrue(transport.observeState().value() is TransportState.Error)

        transport.disconnect()

        // The fix under test: previously this returned instantly with ZERO
        // startService calls at all. Now it must genuinely ask the service
        // to stop.
        assertEquals(1, lastStartedStopIntentCount())
        // No real service ever confirms STOPPED in this test (Robolectric
        // never dispatches onStartCommand for a startService() call) - the
        // bounded wait must still resolve to Disconnected rather than
        // leaving the caller stuck on Disconnecting forever.
        assertEquals(TransportState.Disconnected, transport.observeState().value())
    }

    @Test
    fun `repeated disconnect after reaching Disconnected is idempotent - no second stop intent`() = runTest {
        val transport = ShadowsocksTransport(context, disconnectConfirmTimeoutMillis = 50L)
        val config = net.pocvpn.client.vpn.config.TransportConfig.Shadowsocks(
            endpointId = net.pocvpn.client.reachability.EndpointId("frankfurt"),
            host = "152.70.43.1",
            port = 28388,
        )
        transport.connect(config)
        transport.disconnect()
        assertEquals(1, lastStartedStopIntentCount())

        transport.disconnect()

        assertEquals(0, lastStartedStopIntentCount())
        assertEquals(TransportState.Disconnected, transport.observeState().value())
    }

    @Test
    fun `disconnect during a partial-failed startup (permission never granted) is safe and terminal`() = runTest {
        val transport = ShadowsocksTransport(context, disconnectConfirmTimeoutMillis = 50L)
        val config = net.pocvpn.client.vpn.config.TransportConfig.Shadowsocks(
            endpointId = net.pocvpn.client.reachability.EndpointId("frankfurt"),
            host = "152.70.43.1",
            port = 28388,
        )
        // connect() never even reaches the service (permission denied) - this
        // is the "partial/failed startup" case the physical bug report asked
        // to be covered.
        transport.connect(config)
        assertTrue(transport.observeState().value() is TransportState.Error)

        transport.disconnect()
        transport.disconnect()

        assertEquals(TransportState.Disconnected, transport.observeState().value())
    }
}

/** kotlinx.coroutines StateFlow has no public synchronous `.value()` under the Flow interface used here - this reads the same [ShadowsocksTransport.observeState] value a real caller would. */
private fun kotlinx.coroutines.flow.Flow<TransportState>.value(): TransportState =
    (this as kotlinx.coroutines.flow.StateFlow<TransportState>).value
