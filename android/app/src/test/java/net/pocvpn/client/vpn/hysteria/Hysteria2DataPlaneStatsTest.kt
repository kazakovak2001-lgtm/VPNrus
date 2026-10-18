package net.pocvpn.client.vpn.hysteria

import java.io.File
import java.io.IOException
import java.io.StringReader
import net.pocvpn.client.transport.TransportStats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

private fun line(pid: Int = 4242, seq: Long, tx: Long, rx: Long) = """{"type":"stats","pid":$pid,"seq":$seq,"tx":$tx,"rx":$rx}"""

/** H2-GATE (S2) - parsing, fail-closed tracking and session scoping of the tun2socks child's stats stream. */
class Hysteria2DataPlaneStatsTest {

    private var now = 10_000L
    private fun tracker() = Hysteria2DataPlaneStatsTracker(expectedPid = 4242, nowMillis = { now })

    @Test
    fun `strict parse accepts only the exact counters-only line`() {
        assertEquals(Tun2SocksStatsLine(4242, 1, 10, 20), parseTun2SocksStatsLine(line(seq = 1, tx = 10, rx = 20)))
        assertNull(parseTun2SocksStatsLine("""{"type":"other","pid":1,"seq":1,"tx":0,"rx":0}"""))
        assertNull(parseTun2SocksStatsLine("""{"type":"stats","pid":1,"seq":1,"tx":0}"""))
        assertNull(parseTun2SocksStatsLine("""{"type":"stats","pid":1,"seq":1,"tx":0,"rx":0,"addr":"1.1.1.1"}"""))
        assertNull(parseTun2SocksStatsLine("""{"type":"stats","pid":1,"seq":1,"tx":-1,"rx":0}"""))
        assertNull(parseTun2SocksStatsLine("""{"type":"stats","pid":1,"seq":0,"tx":0,"rx":0}"""))
        assertNull(parseTun2SocksStatsLine("not json"))
    }

    @Test
    fun `no line yet is Unavailable - never zero counters`() {
        assertEquals(TransportStats.Unavailable, tracker().snapshot())
    }

    @Test
    fun `a fresh valid line is reported as counters, rx and tx not swapped`() {
        val t = tracker()
        t.accept(line(seq = 1, tx = 300, rx = 900))
        assertEquals(TransportStats.Counters(bytesReceived = 900, bytesSent = 300, lastHandshakeEpochMillis = null), t.snapshot())
    }

    @Test
    fun `a stream that goes quiet is stale (Unavailable), and resumes when lines arrive again`() {
        val t = tracker()
        t.accept(line(seq = 1, tx = 1, rx = 1))
        now += Hysteria2DataPlaneStatsTracker.STALE_AFTER_MILLIS + 1
        assertEquals(TransportStats.Unavailable, t.snapshot())
        t.accept(line(seq = 2, tx = 2, rx = 2))
        assertTrue(t.snapshot() is TransportStats.Counters)
    }

    @Test
    fun `another child's pid breaks the session permanently`() {
        val t = tracker()
        t.accept(line(seq = 1, tx = 1, rx = 1))
        t.accept(line(pid = 1, seq = 2, tx = 2, rx = 2))
        assertEquals(TransportStats.Unsupported, t.snapshot())
        t.accept(line(seq = 3, tx = 3, rx = 3))
        assertEquals(TransportStats.Unsupported, t.snapshot())
    }

    @Test
    fun `replayed or reordered seq and counters going backwards break the session`() {
        for (bad in listOf(line(seq = 1, tx = 5, rx = 5), line(seq = 3, tx = 4, rx = 9), line(seq = 3, tx = 9, rx = 4), "garbage")) {
            val t = tracker()
            t.accept(line(seq = 1, tx = 5, rx = 5))
            t.accept(bad)
            assertEquals(bad, TransportStats.Unsupported, t.snapshot())
        }
    }

    @Test
    fun `a stream end is permanent - no evidence can follow`() {
        val t = tracker()
        t.accept(line(seq = 1, tx = 1, rx = 1))
        t.streamEnded()
        t.accept(line(seq = 2, tx = 2, rx = 2))
        assertEquals(TransportStats.Unsupported, t.snapshot())
    }

    @Test
    fun `bounded line reader rejects an over-long or truncated line instead of shortening it`() {
        assertEquals("abc", readBoundedLine(StringReader("abc\n"), 8))
        assertNull(readBoundedLine(StringReader(""), 8))
        try {
            readBoundedLine(StringReader("x".repeat(9) + "\n"), 8)
            fail("over-long line accepted")
        } catch (expected: IOException) {
        }
        try {
            readBoundedLine(StringReader("abc"), 8)
            fail("truncated line accepted")
        } catch (expected: IOException) {
        }
    }

    @Test
    fun `ack parses the stats capability marker, an older child has none`() {
        assertEquals(Hysteria2Tun2SocksChildAck.Ok(pid = 7, streamsStats = true), parseTun2SocksChildAck("""{"ok":true,"pid":7,"socksAuth":true,"stats":true}"""))
        assertEquals(Hysteria2Tun2SocksChildAck.Ok(pid = 7, streamsStats = false), parseTun2SocksChildAck("""{"ok":true,"pid":7,"socksAuth":true}"""))
    }

    private class StatsChannel(private val ack: Hysteria2Tun2SocksChildAck) : Hysteria2Tun2SocksChildControlChannel {
        var tracker: Hysteria2DataPlaneStatsTracker? = null
        override fun bind(socketPath: File) = Unit
        override fun sendStartRequestAndAwaitAck(fd: Int, mtu: Int, socksAddr: String, socksUser: String, socksPass: String, timeoutMillis: Long) = ack
        override fun startStatsReader(tracker: Hysteria2DataPlaneStatsTracker, timeoutMillis: Long) {
            this.tracker = tracker
        }
        override fun close() = Unit
    }

    private class Child : Hysteria2Tun2SocksChildProcess {
        var alive = true
        var onExitCallback: ((Int) -> Unit)? = null
        override fun isAlive() = alive
        override fun requestStop() {
            alive = false
            onExitCallback?.invoke(0)
        }
        override fun forceStop() {
            alive = false
        }
        override fun waitForExit(timeoutMillis: Long): Int? = if (alive) null else 0
        override fun onExit(callback: (Int) -> Unit) {
            onExitCallback = callback
        }
    }

    private fun runtime(ack: Hysteria2Tun2SocksChildAck, child: Child = Child()): Pair<Hysteria2Tun2SocksChildRuntime, StatsChannel> {
        val channel = StatsChannel(ack)
        val launcher = object : Hysteria2Hysteria2Tun2SocksChildProcessLauncher {
            override fun launch(binaryPath: String, args: List<String>): Hysteria2Tun2SocksChildProcess = child
        }
        val rt = Hysteria2Tun2SocksChildRuntime(launcher, channel, { }, nowMillis = { now })
        val result = rt.start(42, 1500, "127.0.0.1:41999", "u", "p", "/fake/bin", File("/tmp/h2gate.sock"))
        assertEquals(Hysteria2Tun2SocksChildResult.Ok(ack.let { (it as Hysteria2Tun2SocksChildAck.Ok).pid }), result)
        return rt to channel
    }

    @Test
    fun `runtime exposes the current child's counters, bound to that child's pid`() {
        val (rt, channel) = runtime(Hysteria2Tun2SocksChildAck.Ok(pid = 4242, streamsStats = true))
        assertEquals(TransportStats.Unavailable, rt.dataPlaneCounters())
        channel.tracker!!.accept(line(seq = 1, tx = 3, rx = 4))
        assertEquals(TransportStats.Counters(4, 3, null), rt.dataPlaneCounters())
    }

    @Test
    fun `a child without the stats marker gets no reader and reports Unsupported`() {
        val (rt, channel) = runtime(Hysteria2Tun2SocksChildAck.Ok(pid = 4242, streamsStats = false))
        assertNull(channel.tracker)
        assertEquals(TransportStats.Unsupported, rt.dataPlaneCounters())
    }

    @Test
    fun `stopped or unexpectedly dead child reports Unsupported, never its last counters`() {
        val (stopped, stoppedChannel) = runtime(Hysteria2Tun2SocksChildAck.Ok(pid = 4242, streamsStats = true))
        stoppedChannel.tracker!!.accept(line(seq = 1, tx = 3, rx = 4))
        stopped.stop()
        assertEquals(TransportStats.Unsupported, stopped.dataPlaneCounters())

        val child = Child()
        val (dead, deadChannel) = runtime(Hysteria2Tun2SocksChildAck.Ok(pid = 4242, streamsStats = true), child)
        deadChannel.tracker!!.accept(line(seq = 1, tx = 3, rx = 4))
        child.alive = false
        child.onExitCallback!!.invoke(137)
        assertEquals(TransportStats.Unsupported, dead.dataPlaneCounters())
    }

    @Test
    fun `service counters are readable only for the session that owns them`() {
        Hysteria2VpnService.dataPlaneSource = Hysteria2VpnService.Companion.DataPlaneSource(7L) { TransportStats.Counters(1, 1, null) }
        try {
            assertTrue(Hysteria2VpnService.dataPlaneCounters(7L) is TransportStats.Counters)
            assertEquals(TransportStats.Unsupported, Hysteria2VpnService.dataPlaneCounters(6L))
            Hysteria2VpnService.clearDataPlaneSource(6L)
            assertTrue("a stale session must not clear the current one", Hysteria2VpnService.dataPlaneCounters(7L) is TransportStats.Counters)
            Hysteria2VpnService.clearDataPlaneSource(7L)
            assertEquals(TransportStats.Unsupported, Hysteria2VpnService.dataPlaneCounters(7L))
        } finally {
            Hysteria2VpnService.dataPlaneSource = null
        }
    }
}
