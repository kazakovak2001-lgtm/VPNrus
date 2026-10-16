package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DataPlaneCheckLogTest {

    private var now = 1_000L
    private val xray = TrafficProgressPolicy.forTransport(TransportKind.XRAY_REALITY)

    private fun log(capacity: Int = 10) = DataPlaneCheckLog(capacity) { now }

    private fun sample(ms: Long, rx: Long, tx: Long) = TrafficProgressSample(ms, rx, tx)

    @Test
    fun `an empty log reports NOT_RUN with the nominal time basis`() {
        val json = DataPlaneCheckLog.reportJson(log().snapshot())
        assertEquals("NOT_RUN", json.getString("status"))
        assertEquals(0, json.getJSONArray("items").length())
        assertTrue(json.getString("timeBasis").contains("NOMINAL"))
    }

    @Test
    fun `a started check is RUNNING with no verdict, end or finish time`() {
        val l = log()
        val id = l.start(TransportKind.XRAY_REALITY, xray, 150)
        val r = l.snapshot().single()
        assertEquals(id, r.checkId)
        assertEquals(DataPlaneCheckStatus.RUNNING, r.status)
        assertEquals(TrafficProgressVerdict.VERIFYING, r.verdict)
        assertNull(r.end)
        assertNull(r.finishedAtEpochMillis)
        assertNull(r.silentForMs)
    }

    @Test
    fun `a completed check carries every field and serializes them`() {
        val l = log()
        val id = l.start(TransportKind.TLS_TCP, TrafficProgressPolicy.forTransport(TransportKind.TLS_TCP), 150)
        now = 66_000L
        l.complete(id, TrafficProgressVerdict.NO_PAYLOAD, listOf(sample(0, 0, 0), sample(65_000, 0, 9_000)), 131, TrafficProgressCheckEnd.DECISIVE_VERDICT)

        val json = l.snapshot().single().toJson()
        assertEquals(id, json.getLong("checkId"))
        assertEquals("TLS_TCP", json.getString("transport"))
        assertEquals("COMPLETED", json.getString("status"))
        assertEquals("NO_PAYLOAD", json.getString("verdict"))
        assertEquals(65_000L, json.getLong("stallWindowMs"))
        assertEquals(10_000L, json.getLong("verificationWindowMs"))
        assertEquals(65_000L, json.getLong("silentForMs"))
        assertEquals(2, json.getInt("samples"))
        assertEquals(131, json.getInt("polls"))
        assertEquals(150, json.getInt("maxPolls"))
        assertEquals("DECISIVE_VERDICT", json.getString("end"))
        assertEquals(1_000L, json.getLong("startedAtEpochMillis"))
        assertEquals(66_000L, json.getLong("finishedAtEpochMillis"))
    }

    @Test
    fun `an interrupted check is CANCELLED or ABORTED with no end, and a final record is never overwritten`() {
        val l = log()
        val cancelled = l.start(TransportKind.XRAY_REALITY, xray, 150)
        l.interrupt(cancelled, cancelled = true, verdict = TrafficProgressVerdict.VERIFYING, samples = listOf(sample(0, 0, 0)), polls = 1)
        val aborted = l.start(TransportKind.XRAY_REALITY, xray, 150)
        l.interrupt(aborted, cancelled = false, verdict = TrafficProgressVerdict.VERIFYING, samples = emptyList(), polls = 0)
        // A late completion of an already-final record changes nothing.
        l.complete(cancelled, TrafficProgressVerdict.NO_PAYLOAD, listOf(sample(0, 0, 0), sample(65_000, 0, 9)), 131, TrafficProgressCheckEnd.DECISIVE_VERDICT)

        val (first, second) = l.snapshot()
        assertEquals(DataPlaneCheckStatus.CANCELLED, first.status)
        assertEquals(TrafficProgressVerdict.VERIFYING, first.verdict)
        assertNull(first.end)
        assertEquals(1, first.polls)
        assertEquals(DataPlaneCheckStatus.ABORTED, second.status)
        assertNull(second.silentForMs)
    }

    @Test
    fun `each check gets its own increasing id - a later session never inherits an earlier verdict`() {
        val l = log()
        val a = l.start(TransportKind.AMNEZIA_WG, TrafficProgressPolicy.forTransport(TransportKind.AMNEZIA_WG), 60)
        l.complete(a, TrafficProgressVerdict.VERIFIED, listOf(sample(0, 0, 0), sample(500, 1, 1), sample(10_000, 2, 2)), 21, TrafficProgressCheckEnd.DECISIVE_VERDICT)
        val b = l.start(TransportKind.XRAY_REALITY, xray, 150)

        assertTrue(b > a)
        val (first, second) = l.snapshot()
        assertEquals(TrafficProgressVerdict.VERIFIED, first.verdict)
        assertEquals(DataPlaneCheckStatus.RUNNING, second.status)
        assertEquals(TrafficProgressVerdict.VERIFYING, second.verdict)
    }

    @Test
    fun `the log is bounded and keeps the newest records`() {
        val l = log(capacity = 2)
        val ids = (1..3).map { l.start(TransportKind.XRAY_REALITY, xray, 150) }
        assertEquals(ids.drop(1), l.snapshot().map { it.checkId })
        // Finishing an evicted record is a no-op.
        l.interrupt(ids[0], cancelled = true, verdict = TrafficProgressVerdict.VERIFYING, samples = emptyList(), polls = 0)
        assertEquals(2, l.snapshot().size)
    }

    @Test
    fun `reading the log does not consume or alter it`() {
        val l = log()
        l.start(TransportKind.XRAY_REALITY, xray, 150)
        val first = DataPlaneCheckLog.reportJson(l.snapshot()).toString()
        val second = DataPlaneCheckLog.reportJson(l.snapshot()).toString()
        assertEquals(first, second)
        assertEquals("RECORDED", DataPlaneCheckLog.reportJson(l.snapshot()).getString("status"))
    }
}
