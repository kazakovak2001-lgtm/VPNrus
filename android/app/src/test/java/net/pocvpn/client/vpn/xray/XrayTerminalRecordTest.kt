package net.pocvpn.client.vpn.xray

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The `:xray` -> main terminal-event record (storage) and its `:xray`-side
 * journal (policy), both on a real file.
 */
class XrayTerminalRecordTest {

    @get:Rule val tmp = TemporaryFolder()

    private fun file() = File(tmp.root, "xray-terminal-event")
    private fun record() = XrayTerminalRecord(file())

    private fun XrayTerminalJournal.publish(event: XrayRuntimeEvent): Boolean = synchronized(lock) { onPublish(event) }

    // --- storage --------------------------------------------------------------------

    @Test
    fun `Stopped and a typed Failed round-trip`() {
        val r = record()
        assertTrue(r.write(XrayRuntimeEvent.Stopped(42L)))
        assertEquals(XrayRuntimeEvent.Stopped(42L), r.read())

        val relayLost = XrayRuntimeState.relayHealthLostEvent(43L, TransportKind.XRAY_XHTTP)
        r.write(relayLost)
        assertEquals(relayLost, r.read())
    }

    @Test
    fun `Started is never recorded`() {
        val r = record()
        r.write(XrayRuntimeEvent.Stopped(1L))
        assertFalse(r.write(XrayRuntimeEvent.Started(2L)))
        assertEquals(XrayRuntimeEvent.Stopped(1L), r.read())
    }

    @Test
    fun `missing, malformed and tombstoned files read as no record`() {
        val r = record()
        assertNull(r.read())
        file().writeText("garbage")
        assertNull(r.read())
        file().writeText("failed\nnot-a-number\n\nx")
        assertNull(r.read())
        file().writeText("cleared\n0\n\n")
        assertNull(r.read())
    }

    @Test
    fun `a newline in the reason cannot break the format`() {
        val r = record()
        r.write(XrayRuntimeEvent.Failed(7L, "line one\nline two"))
        assertEquals(XrayRuntimeEvent.Failed(7L, "line one line two"), r.read())
    }

    @Test
    fun `an unwritable location fails the write and reads as no record`() {
        val blocker = File(tmp.root, "not-a-dir").apply { writeText("x") } // a FILE where the directory should be
        val r = XrayTerminalRecord(File(blocker, "xray-terminal-event"))

        assertFalse(r.write(XrayRuntimeEvent.Stopped(5L)))
        assertNull(r.read())
    }

    @Test
    fun `clear removes the record and leaves no temp files behind`() {
        val r = record()
        r.write(XrayRuntimeEvent.Stopped(8L))
        assertTrue(r.clear())
        assertNull(r.read())
        assertEquals(emptyList<String>(), tmp.root.list()!!.toList())
    }

    @Test
    fun `a new reader instance reads what another instance wrote`() {
        record().write(XrayRuntimeEvent.Failed(9L, "boom"))
        assertEquals(XrayRuntimeEvent.Failed(9L, "boom"), record().read())
    }

    @Test
    fun `parallel writers never produce a partial or mixed record`() {
        val writers = 8
        val perWriter = 200
        val plan = (0 until writers).map { w ->
            (0 until perWriter).map { i ->
                if ((w + i) % 2 == 0) XrayRuntimeEvent.Stopped(1_000L + w)
                else XrayRuntimeEvent.Failed(1_000L + w, "writer $w event $i " + "x".repeat(40 + i % 50))
            }
        }
        val valid = plan.flatten().toSet()
        val r = record()
        val start = CountDownLatch(1)
        val done = AtomicBoolean(false)
        val seen = Collections.synchronizedList(mutableListOf<XrayRuntimeEvent?>())
        val reader = Thread {
            start.await()
            while (!done.get()) seen += XrayTerminalRecord(file()).read()
        }.apply { start() }
        val threads = plan.map { events -> Thread { start.await(); events.forEach { r.write(it) } }.apply { start() } }
        start.countDown()
        threads.forEach { it.join() }
        done.set(true)
        reader.join()

        assertTrue(seen.isNotEmpty())
        seen.filterNotNull().forEach { assertTrue("mixed record $it", it in valid) }
        assertTrue(r.read() in valid)
        assertTrue(tmp.root.list()!!.none { it.endsWith(".tmp") })
    }

    // --- journal (`:xray` policy) ------------------------------------------------------

    @Test
    fun `Started clears a record left by an earlier session, process or app run`() {
        record().write(XrayRuntimeEvent.Stopped(77L)) // left behind before this process existed
        val journal = XrayTerminalJournal(record())

        journal.publish(XrayRuntimeEvent.Started(5L)) // even an id lower than the stale one (clock moved back)

        assertNull(record().read())
    }

    @Test
    fun `only the owned session's first terminal event is recorded`() {
        val journal = XrayTerminalJournal(record())
        journal.publish(XrayRuntimeEvent.Started(10L))
        val relayLost = XrayRuntimeState.relayHealthLostEvent(10L, TransportKind.XRAY_XHTTP)

        assertTrue(journal.publish(relayLost))
        assertFalse(journal.publish(XrayRuntimeEvent.Stopped(10L))) // later onRevoke/onDestroy for the same session

        assertEquals(relayLost, record().read())
    }

    @Test
    fun `a late terminal event of session N neither replaces nor erases session N+1's record`() {
        val journal = XrayTerminalJournal(record())
        journal.publish(XrayRuntimeEvent.Started(20L))
        journal.publish(XrayRuntimeEvent.Started(21L))
        assertTrue(journal.publish(XrayRuntimeEvent.Failed(21L, "n+1 failed")))

        assertFalse(journal.publish(XrayRuntimeEvent.Stopped(20L))) // late teardown of N

        assertEquals(XrayRuntimeEvent.Failed(21L, "n+1 failed"), record().read())
    }

    @Test
    fun `terminal events of a session this process never started are not recorded`() {
        val journal = XrayTerminalJournal(record())
        assertFalse(journal.publish(XrayRuntimeEvent.Failed(30L, "start failed before Started")))
        journal.publish(XrayRuntimeEvent.Started(31L))
        assertFalse(journal.publish(XrayRuntimeEvent.Failed(30L, "late")))
        assertNull(record().read())
    }

    @Test
    fun `parallel terminal publishes for one session record exactly one complete event`() {
        val journal = XrayTerminalJournal(record())
        journal.publish(XrayRuntimeEvent.Started(40L))
        val events = listOf(
            XrayRuntimeState.relayHealthLostEvent(40L, TransportKind.XRAY_XHTTP), // relay watchdog
            XrayRuntimeEvent.Stopped(40L), // onRevoke
            XrayRuntimeEvent.Stopped(40L), // onDestroy
            XrayRuntimeEvent.Failed(40L, "other"),
        )
        val start = CountDownLatch(1)
        val wins = Collections.synchronizedList(mutableListOf<XrayRuntimeEvent>())
        val threads = events.map { e -> Thread { start.await(); if (journal.publish(e)) wins += e }.apply { start() } }
        start.countDown()
        threads.forEach { it.join() }

        assertEquals(1, wins.size)
        assertEquals(wins.single(), record().read())
    }

    @Test(expected = IllegalStateException::class)
    fun `onPublish refuses to run outside the journal lock`() {
        XrayTerminalJournal(record()).onPublish(XrayRuntimeEvent.Started(1L))
    }
}
