@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.TransportFailureKind
import net.pocvpn.client.vpn.TransportState
import net.pocvpn.client.vpn.xrayTransportStateFor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Proxy
import java.util.concurrent.atomic.AtomicLong

/**
 * The real main-process death watch ([XrayProcessWatcher]) and broadcast
 * path ([XrayProcessBridge.deliverFromService]) driven end to end on the
 * JVM: bind/unbind, the grace scheduler and the terminal record are the
 * only seams; the binder death arrives through the DeathRecipient the
 * watcher itself registers in onServiceConnected.
 *
 * Every test uses fresh, increasing session ids because the mirror
 * ([XrayRuntimeState]) is process-global and rejects older sessions.
 */
class XrayProcessWatcherTest {

    private companion object {
        val ids = AtomicLong(9_300_000_000_000_000L)
    }

    private fun nextId(): Long = ids.addAndGet(10)

    private class Harness(val record: () -> XrayRuntimeEvent?) {
        var binds = 0
        var unbinds = 0
        val graces = mutableListOf<() -> Unit>()
        var recipient: IBinder.DeathRecipient? = null

        val watcher = XrayProcessWatcher(
            context = null,
            bind = { binds++; true },
            unbind = { unbinds++ },
            scheduleGrace = { _, block -> graces += block },
            readTerminalRecord = record,
        )

        /** What Android does after a successful bind: hands us the service binder (we link to its death). */
        fun connect() {
            val binder = Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) { _, method, args ->
                when (method.name) {
                    "linkToDeath" -> { recipient = args!![0] as IBinder.DeathRecipient; null }
                    "unlinkToDeath" -> true
                    "isBinderAlive", "pingBinder" -> true
                    else -> null
                }
            } as IBinder
            watcher.onServiceConnected(null, binder)
        }

        fun processDies() = requireNotNull(recipient) { "watcher never linked to death" }.binderDied()

        fun deliver(event: XrayRuntimeEvent) = XrayProcessBridge.deliverFromService(event, watcher)
    }

    private fun startedSession(record: () -> XrayRuntimeEvent? = { null }): Pair<Harness, Long> {
        val h = Harness(record)
        val id = nextId()
        assertTrue(h.deliver(XrayRuntimeEvent.Started(id)))
        assertEquals(id, h.watcher.watching)
        h.connect()
        return h to id
    }

    @Test
    fun `an unexpected death publishes Failed at once and ends the watch`() {
        val (h, id) = startedSession()

        h.processDies()

        assertEquals(XrayRuntimeEvent.Failed(id, XrayProcessBridge.DIED_REASON), XrayRuntimeState.events.value)
        assertTrue(h.graces.isEmpty())
        assertNull(h.watcher.watching)
        assertEquals(1, h.unbinds)
    }

    @Test
    fun `onBindingDied is handled exactly like a death`() {
        val (h, id) = startedSession()

        h.watcher.onBindingDied(null)

        assertEquals(XrayRuntimeEvent.Failed(id, XrayProcessBridge.DIED_REASON), XrayRuntimeState.events.value)
        assertNull(h.watcher.watching)
    }

    @Test
    fun `an expected stop keeps the grace and the late Stopped broadcast wins`() {
        val (h, id) = startedSession()
        XrayProcessBridge.stopSession(id) { }

        h.processDies()
        assertEquals(XrayRuntimeEvent.Started(id), XrayRuntimeState.events.value)
        assertEquals(1, h.graces.size)

        assertTrue(h.deliver(XrayRuntimeEvent.Stopped(id)))
        h.graces.single().invoke()

        assertEquals(XrayRuntimeEvent.Stopped(id), XrayRuntimeState.events.value)
    }

    @Test
    fun `an expected stop whose Stopped never arrives fails after the grace`() {
        val (h, id) = startedSession()
        XrayProcessBridge.stopSession(id) { }

        h.processDies()
        h.graces.single().invoke()

        assertEquals(XrayRuntimeEvent.Failed(id, XrayProcessBridge.DIED_REASON), XrayRuntimeState.events.value)
    }

    @Test
    fun `a system VPN revoke recorded by the service stays Stopped even if the death comes first`() {
        var record: XrayRuntimeEvent? = null
        val (h, id) = startedSession { record }
        record = XrayRuntimeEvent.Stopped(id) // onRevoke -> teardown -> publishFromService wrote it before stopSelf

        h.processDies()

        assertEquals(XrayRuntimeEvent.Stopped(id), XrayRuntimeState.events.value)
        assertTrue(h.graces.isEmpty())
        assertFalse(h.deliver(XrayRuntimeEvent.Stopped(id))) // the broadcast itself, late: a duplicate
    }

    @Test
    fun `RELAY_DATA_PLANE_LOST survives a death that beats its broadcast`() {
        var record: XrayRuntimeEvent? = null
        val (h, id) = startedSession { record }
        val relayLost = XrayRuntimeState.relayHealthLostEvent(id, TransportKind.XRAY_XHTTP)
        record = relayLost

        h.processDies()
        assertFalse(h.deliver(relayLost)) // late broadcast

        val mirrored = XrayRuntimeState.events.value as XrayRuntimeEvent.Failed
        assertEquals(TransportFailureKind.RELAY_DATA_PLANE_LOST, mirrored.failureKind)
        assertEquals(
            TransportState.Error(relayLost.reason, failureKind = TransportFailureKind.RELAY_DATA_PLANE_LOST),
            xrayTransportStateFor(mirrored, id),
        )
    }

    @Test
    fun `duplicate terminal events reach the transports exactly once`() = runTest(UnconfinedTestDispatcher()) {
        val (h, id) = startedSession()
        val errors = mutableListOf<TransportState>()
        val job = launch { XrayRuntimeState.events.collect { e -> xrayTransportStateFor(e, id)?.takeIf { it is TransportState.Error }?.let(errors::add) } }

        h.processDies() // death-time Failed
        h.deliver(XrayRuntimeEvent.Failed(id, "late service reason")) // dropped
        h.deliver(XrayRuntimeEvent.Stopped(id)) // dropped

        assertEquals(1, errors.size) // one Error -> one failover trigger downstream
        job.cancel()
    }

    @Test
    fun `a late terminal event of session N neither unwatches nor overrides session N+1`() {
        val (h, old) = startedSession()
        val new = nextId()
        assertTrue(h.deliver(XrayRuntimeEvent.Started(new)))
        h.connect()

        assertFalse(h.deliver(XrayRuntimeEvent.Stopped(old)))
        assertFalse(h.deliver(XrayRuntimeEvent.Failed(old, "late")))
        assertEquals(new, h.watcher.watching)
        assertEquals(XrayRuntimeEvent.Started(new), XrayRuntimeState.events.value)

        h.processDies() // the NEW session's process dies: still detected
        assertEquals(XrayRuntimeEvent.Failed(new, XrayProcessBridge.DIED_REASON), XrayRuntimeState.events.value)
    }

    @Test
    fun `the watcher itself ignores another session's terminal event`() {
        val (h, id) = startedSession()

        h.watcher.onEvent(XrayRuntimeEvent.Stopped(id - 5))
        h.watcher.onEvent(XrayRuntimeEvent.Started(id - 5))

        assertEquals(id, h.watcher.watching)
    }

    @Test
    fun `a reconnect while an old session's grace is pending never fails the new session`() {
        val (h, old) = startedSession()
        XrayProcessBridge.stopSession(old) { }
        h.processDies()
        val grace = h.graces.single()

        val new = nextId()
        assertTrue(h.deliver(XrayRuntimeEvent.Started(new)))
        grace.invoke() // the old session's grace fires after the reconnect

        assertEquals(XrayRuntimeEvent.Started(new), XrayRuntimeState.events.value)
        assertEquals(new, h.watcher.watching)
    }
}
