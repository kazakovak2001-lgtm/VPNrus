package net.pocvpn.client.vpn.traffic

import net.pocvpn.client.transport.TransportStats
import org.junit.Assert.assertEquals
import org.junit.Test

class TrafficRateMeterTest {

    private fun counters(rx: Long, tx: Long) = TransportStats.Counters(bytesReceived = rx, bytesSent = tx, lastHandshakeEpochMillis = null)

    @Test
    fun `first sample is Measuring, never a rate`() {
        assertEquals(TrafficRate.Measuring, TrafficRateMeter().update(1_000, counters(5_000_000, 1_000_000)))
    }

    @Test
    fun `no traffic is a genuine zero rate`() {
        val meter = TrafficRateMeter()
        meter.update(0, counters(100, 100))
        assertEquals(TrafficRate.Rate(0, 0), meter.update(1_000, counters(100, 100)))
        assertEquals(TrafficRate.Rate(0, 0), meter.update(2_000, counters(100, 100)))
    }

    @Test
    fun `increasing counters give download and upload rates from deltas over elapsed time`() {
        val meter = TrafficRateMeter()
        meter.update(0, counters(0, 0))
        // 2.4 MB down and 180 kB up in 1 s; first interval is unsmoothed.
        assertEquals(TrafficRate.Rate(2_400_000, 180_000), meter.update(1_000, counters(2_400_000, 180_000)))
        // 1 MB down over 2 s = 500 kB/s.
        val meter2 = TrafficRateMeter()
        meter2.update(10_000, counters(0, 0))
        assertEquals(TrafficRate.Rate(500_000, 0), meter2.update(12_000, counters(1_000_000, 0)))
    }

    @Test
    fun `smoothing is a modest EMA and two idle intervals snap to zero`() {
        val meter = TrafficRateMeter(smoothing = 0.5)
        meter.update(0, counters(0, 0))
        meter.update(1_000, counters(1_000_000, 0)) // 1 MB/s
        assertEquals(TrafficRate.Rate(1_500_000, 0), meter.update(2_000, counters(3_000_000, 0))) // 0.5*2M + 0.5*1M
        assertEquals(TrafficRate.Rate(750_000, 0), meter.update(3_000, counters(3_000_000, 0))) // first idle interval decays
        assertEquals(TrafficRate.Rate(0, 0), meter.update(4_000, counters(3_000_000, 0))) // second idle interval: real zero
    }

    @Test
    fun `counter reset re-baselines instead of producing a negative or absurd rate`() {
        val meter = TrafficRateMeter()
        meter.update(0, counters(10_000_000, 5_000_000))
        meter.update(1_000, counters(11_000_000, 5_100_000))
        assertEquals(TrafficRate.Measuring, meter.update(2_000, counters(1_000, 500)))
        assertEquals(TrafficRate.Rate(1_000, 500), meter.update(3_000, counters(2_000, 1_000)))
    }

    @Test
    fun `a reset of only one direction also re-baselines`() {
        val meter = TrafficRateMeter()
        meter.update(0, counters(1_000, 1_000))
        assertEquals(TrafficRate.Measuring, meter.update(1_000, counters(2_000, 10)))
    }

    @Test
    fun `non-advancing clock keeps the baseline and never divides by zero`() {
        val meter = TrafficRateMeter()
        meter.update(1_000, counters(0, 0))
        assertEquals(TrafficRate.Measuring, meter.update(1_000, counters(1_000_000, 0)))
        assertEquals(TrafficRate.Measuring, meter.update(500, counters(1_000_000, 0)))
        // Baseline is still the t=1000 sample.
        assertEquals(TrafficRate.Rate(1_000_000, 0), meter.update(2_000, counters(1_000_000, 0)))
    }

    @Test
    fun `a gap longer than the max interval re-baselines`() {
        val meter = TrafficRateMeter(maxIntervalMillis = 10_000)
        meter.update(0, counters(0, 0))
        assertEquals(TrafficRate.Measuring, meter.update(60_000, counters(60_000_000, 0)))
    }

    @Test
    fun `unavailable or unsupported counters are Unavailable, never zero, and reset the baseline`() {
        val meter = TrafficRateMeter()
        meter.update(0, counters(0, 0))
        assertEquals(TrafficRate.Unavailable, meter.update(1_000, TransportStats.Unavailable))
        assertEquals(TrafficRate.Unavailable, meter.update(2_000, TransportStats.Unsupported))
        assertEquals(TrafficRate.Unavailable, meter.update(3_000, TransportStats.NotImplemented))
        assertEquals(TrafficRate.Unavailable, meter.update(4_000, counters(-1, 0)))
        // Next valid reading starts over from a fresh baseline.
        assertEquals(TrafficRate.Measuring, meter.update(5_000, counters(9_000_000, 0)))
    }

    @Test
    fun `format uses decimal units with clear thresholds`() {
        assertEquals("0 B/s", TrafficRateFormat.speed(0))
        assertEquals("999 B/s", TrafficRateFormat.speed(999))
        assertEquals("1.0 kB/s", TrafficRateFormat.speed(1_000))
        assertEquals("180 kB/s", TrafficRateFormat.speed(180_000))
        assertEquals("1.0 MB/s", TrafficRateFormat.speed(999_500))
        assertEquals("2.4 MB/s", TrafficRateFormat.speed(2_400_000))
        assertEquals("125 MB/s", TrafficRateFormat.speed(125_000_000))
        assertEquals("1.2 GB/s", TrafficRateFormat.speed(1_200_000_000))
        assertEquals("0 B/s", TrafficRateFormat.speed(-5))
        assertEquals("↓ 2.4 MB/s  ↑ 180 kB/s", TrafficRateFormat.line(TrafficRate.Rate(2_400_000, 180_000)))
    }
}
