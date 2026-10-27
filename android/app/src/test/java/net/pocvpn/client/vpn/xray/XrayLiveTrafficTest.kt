package net.pocvpn.client.vpn.xray

import android.app.Application
import android.os.DeadObjectException
import android.os.IBinder
import android.os.Parcel
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.lang.reflect.Proxy
import java.util.concurrent.atomic.AtomicLong

/**
 * Live speed indicator - the Xray counter read it polls must never start,
 * restart or re-create `:xray` (see [XrayLiveTraffic]): it only transacts on
 * the death watch's existing binder, and only for the Started session.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class XrayLiveTrafficTest {

    private companion object {
        // Above XrayProcessWatcherTest's range; the mirror is process-global.
        val ids = AtomicLong(9_400_000_000_000_000L)
    }

    private fun nextId(): Long = ids.addAndGet(10)

    @Test
    fun `service binder answers with the folded totals, or none while the core is not running`() {
        val totals = XrayTrafficCounters.Totals(sessionId = 7, uplinkBytes = 180_000, downlinkBytes = 2_400_000)
        assertEquals(totals, XrayLiveTraffic.query(XrayLiveTrafficBinder { totals }))
        assertNull(XrayLiveTraffic.query(XrayLiveTrafficBinder { null }))
    }

    @Test
    fun `service binder does not answer other transaction codes`() {
        val binder = XrayLiveTrafficBinder { XrayTrafficCounters.Totals(1, 1, 1) }
        val data = Parcel.obtain()
        val reply = Parcel.obtain()
        assertFalse(binder.transact(XrayLiveTraffic.TRANSACTION_QUERY_TRAFFIC + 1, data, reply, 0))
        data.recycle()
        reply.recycle()
    }

    @Test
    fun `a dead service binder reads as no totals, never a crash`() {
        val dead = Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) { _, method, _ ->
            if (method.name == "transact") throw DeadObjectException() else null
        } as IBinder
        assertNull(XrayLiveTraffic.query(dead))
    }

    @Test
    fun `not Started - Unavailable without even looking for a binder`() = runTest {
        val id = nextId()
        XrayRuntimeState.publish(XrayRuntimeEvent.Stopped(id))
        var asked = 0
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.liveTrafficStats(id) { asked++; null })
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.liveTrafficStats(null) { asked++; null })
        assertEquals(0, asked)
    }

    @Test
    fun `Started but the watch binder is not connected yet - Unavailable`() = runTest {
        val id = nextId()
        XrayRuntimeState.publish(XrayRuntimeEvent.Started(id))
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.liveTrafficStats(id) { null })
    }

    @Test
    fun `Started session reads its own totals through the binder, another session's never`() = runTest {
        val id = nextId()
        XrayRuntimeState.publish(XrayRuntimeEvent.Started(id))
        val own = XrayLiveTrafficBinder { XrayTrafficCounters.Totals(id, uplinkBytes = 50, downlinkBytes = 1_000) }
        assertEquals(
            TransportStats.Counters(bytesReceived = 1_000, bytesSent = 50, lastHandshakeEpochMillis = null),
            XrayProcessBridge.liveTrafficStats(id) { own },
        )
        val stale = XrayLiveTrafficBinder { XrayTrafficCounters.Totals(id - 1, 50, 1_000) }
        assertEquals(TransportStats.Unavailable, XrayProcessBridge.liveTrafficStats(id) { stale })
    }

    @Test
    fun `polling never issues a start command to the Xray service`() = runTest {
        val app = ApplicationProvider.getApplicationContext<Application>()
        val id = nextId()
        XrayRuntimeState.publish(XrayRuntimeEvent.Started(id))
        val binder = XrayLiveTrafficBinder { XrayTrafficCounters.Totals(id, 1, 1) }
        repeat(5) { XrayProcessBridge.liveTrafficStats(id) { binder } }
        // Teardown race: mirror already Stopped / binder gone.
        XrayRuntimeState.publish(XrayRuntimeEvent.Stopped(id))
        repeat(5) { XrayProcessBridge.liveTrafficStats(id) { binder } }
        assertNull(shadowOf(app).nextStartedService)
    }

    @Test
    fun `watcher hands out the binder only for the watched, connected session and never binds for it`() {
        var binds = 0
        val watcher = XrayProcessWatcher(context = null, bind = { binds++; true }, unbind = { }, scheduleGrace = { _, _ -> }, readTerminalRecord = { null })
        val id = nextId()
        watcher.onEvent(XrayRuntimeEvent.Started(id))
        assertNull("not connected yet", watcher.binderFor(id))
        val service = XrayLiveTrafficBinder { null }
        watcher.onServiceConnected(null, service)
        repeat(3) { assertSame(service, watcher.binderFor(id)) }
        assertNull(watcher.binderFor(id + 1))
        assertEquals("binderFor never binds", 1, binds)
        watcher.onEvent(XrayRuntimeEvent.Stopped(id))
        assertNull(watcher.binderFor(id))
    }
}
