package net.pocvpn.client.vpn.traffic

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.TransportState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VpnTrafficIndicatorTest {

    private class FakeSink : VpnTrafficIndicatorSink {
        val events = mutableListOf<String>()
        var released = 0
        override fun show(rate: TrafficRate) { events += "show:$rate" }
        override fun hide(sessionEnded: Boolean) { events += "hide:$sessionEnded" }
        override fun release() { released++ }
        val shows get() = events.count { it.startsWith("show:") }
    }

    private class Harness(scope: TestScope) {
        val state = MutableStateFlow<TransportState>(TransportState.Disconnected)
        val screenOn = MutableStateFlow(true)
        val sink = FakeSink()
        var rx = 0L
        var tx = 0L
        var stats: () -> TransportStats = { TransportStats.Counters(rx, tx, null) }
        var reads = 0
        val indicator = VpnTrafficIndicator(
            state = state,
            counters = { reads++; stats() },
            sink = sink,
            elapsedRealtimeMillis = { scope.testScheduler.currentTime },
            interactive = screenOn,
        )
    }

    @Test
    fun `starts on Connected, samples about once per second, hides on disconnect`() = runTest {
        val h = Harness(this)
        h.indicator.start(backgroundScope)
        runCurrent()
        assertEquals(listOf("hide:true"), h.sink.events)
        assertEquals(0, h.reads)

        h.state.value = TransportState.Connected
        runCurrent()
        assertEquals("show:${TrafficRate.Measuring}", h.sink.events.last())
        h.rx = 1_000_000
        h.tx = 50_000
        advanceTimeBy(1_000)
        runCurrent()
        assertEquals("show:${TrafficRate.Rate(1_000_000, 50_000)}", h.sink.events.last())
        advanceTimeBy(3_000)
        runCurrent()
        assertEquals(5, h.reads)

        h.state.value = TransportState.Disconnected
        runCurrent()
        assertEquals("hide:true", h.sink.events.last())
        val readsAtDisconnect = h.reads
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals("no sampling after disconnect", readsAtDisconnect, h.reads)
    }

    @Test
    fun `reconnect restarts with a fresh meter and never runs two loops`() = runTest {
        val h = Harness(this)
        h.indicator.start(backgroundScope)
        h.indicator.start(backgroundScope) // idempotent
        h.state.value = TransportState.Connected
        runCurrent()
        h.rx = 5_000_000
        advanceTimeBy(1_000)
        runCurrent()

        h.state.value = TransportState.Reconnecting(1)
        runCurrent()
        assertEquals("hide:true", h.sink.events.last())
        h.state.value = TransportState.Connected
        // New session: counters restart from zero - must not be read as a negative rate.
        h.rx = 0
        runCurrent()
        assertEquals("show:${TrafficRate.Measuring}", h.sink.events.last())

        val before = h.reads
        advanceTimeBy(5_000)
        runCurrent()
        assertEquals("exactly one read per second => one loop", 5, h.reads - before)
        assertTrue(h.sink.events.none { it.contains("-") })
    }

    @Test
    fun `screen off pauses sampling without ending the session`() = runTest {
        val h = Harness(this)
        h.indicator.start(backgroundScope)
        h.state.value = TransportState.Connected
        runCurrent()
        h.screenOn.value = false
        runCurrent()
        assertEquals("hide:false", h.sink.events.last())
        val reads = h.reads
        advanceTimeBy(30_000)
        runCurrent()
        assertEquals(reads, h.reads)

        h.screenOn.value = true
        runCurrent()
        assertEquals("show:${TrafficRate.Measuring}", h.sink.events.last())
    }

    @Test
    fun `unavailable counters are shown as Unavailable, not zero`() = runTest {
        val h = Harness(this)
        h.stats = { TransportStats.Unsupported }
        h.indicator.start(backgroundScope)
        h.state.value = TransportState.Connected
        runCurrent()
        advanceTimeBy(2_000)
        runCurrent()
        assertTrue(h.sink.events.filter { it.startsWith("show:") }.all { it == "show:${TrafficRate.Unavailable}" })
        assertEquals(3, h.sink.shows)
    }

    @Test
    fun `stop cancels sampling, hides and releases the sink`() = runTest {
        val h = Harness(this)
        h.indicator.start(backgroundScope)
        h.state.value = TransportState.Connected
        runCurrent()
        h.indicator.stop()
        val reads = h.reads
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(reads, h.reads)
        assertEquals("hide:true", h.sink.events.last())
        assertEquals(1, h.sink.released)
    }
}
