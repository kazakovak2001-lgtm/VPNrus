package net.pocvpn.client.vpn

import net.pocvpn.client.transport.TransportStats
import net.pocvpn.client.vpn.Hysteria2DataPlaneMonitor.Action
import net.pocvpn.client.vpn.Hysteria2DataPlaneMonitor.ProbeKind
import net.pocvpn.client.vpn.Hysteria2DataPlaneMonitor.State
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private fun c(rx: Long, tx: Long) = TransportStats.Counters(bytesReceived = rx, bytesSent = tx, lastHandshakeEpochMillis = null)

/**
 * H2-GATE Gap A - the pure Hysteria2 data-plane state machine, driven at the
 * controller's 500 ms cadence. Each test names the protection it guards.
 */
class Hysteria2DataPlaneMonitorTest {

    private val m = Hysteria2DataPlaneMonitor()
    private var now = 0L
    private val actions = mutableListOf<Action>()

    private fun sample(stats: TransportStats): List<Action> = m.onSample(stats, now).also { actions += it; now += 500 }

    /** Feeds [polls] samples produced by [f] (poll index -> stats). */
    private fun run(polls: Int, f: (Int) -> TransportStats) = repeat(polls) { sample(f(it)) }

    private fun probes() = actions.filterIsInstance<Action.StartProbe>()

    private fun lastProbe() = probes().last()

    private fun result(ok: Boolean, probe: Action.StartProbe = lastProbe()): List<Action> =
        m.onProbeResult(probe.requestId, probe.epoch, ok, now).also { actions += it }

    /** Healthy traffic until Protected (rx +900 every poll for 11 s). */
    private fun reachProtected(): Long {
        var rx = 0L
        run(23) { rx += 900; c(rx, 0) }
        assertEquals(State.PROTECTED, m.state)
        return rx
    }

    @Test
    fun `promotion needs E-HIST and a fresh rx advance`() {
        reachProtected()
        assertEquals(1, actions.count { it == Action.Promote })
        assertTrue("no probe before the first promotion", probes().isEmpty())
    }

    @Test
    fun `the first Counters sample is only the baseline`() {
        sample(c(5_000, 5_000))
        sample(c(5_000, 5_000))
        // Only an increase over the baseline counts: a large first value is not progress.
        run(30) { c(5_000, 5_000) }
        assertTrue(m.state == State.VERIFYING)
        assertFalse(actions.contains(Action.Promote))
    }

    @Test
    fun `stale history - two early advances then silence - does not promote`() {
        sample(c(0, 0)); sample(c(900, 300)); sample(c(1_800, 600))
        run(20) { c(1_800, 600) }
        assertEquals(State.CONFIRMING, m.state)
        assertFalse(actions.contains(Action.Promote))
        // A later fresh rx advance is the only way out.
        sample(c(2_700, 600))
        assertEquals(State.PROTECTED, m.state)
    }

    @Test
    fun `no probe and no S1-based teardown during initial verification`() {
        run(400) { c(0, 0) } // 200 s of flat counters
        assertTrue(probes().isEmpty())
        assertFalse(actions.any { it is Action.Teardown })
        assertEquals(State.VERIFYING, m.state)
    }

    @Test
    fun `the existing S2 stall verdict still ends an unverified session`() {
        run(140) { c(0, 300L * it) } // tx grows, rx never: NO_PAYLOAD after 65 s
        assertTrue(actions.any { it is Action.Teardown && it.reason == "NO_PAYLOAD" })
        assertEquals(State.TORN_DOWN, m.state)
    }

    @Test
    fun `idle probe success with E-LIVE keeps Protected`() {
        val rx = reachProtected()
        run(120) { c(rx, 0) } // flat for 60 s
        val probe = lastProbe()
        assertEquals(ProbeKind.IDLE, probe.kind)
        assertEquals(State.SUSPECT, m.state)
        result(true)
        assertEquals(State.PROTECTED, m.state)
        assertFalse(actions.contains(Action.Revoke))
        assertEquals(1, probes().size)
        run(120) { c(rx, 0) }
        assertEquals("next idle probe only after another 60 s", 1, probes().size)
        sample(c(rx, 0))
        assertEquals(2, probes().size)
    }

    @Test
    fun `losing E-LIVE while the idle probe is in flight revokes, and its late success is ignored`() {
        val rx = reachProtected()
        run(120) { c(rx, 0) }
        val idle = lastProbe()
        sample(TransportStats.Unavailable)
        assertEquals(State.REVOKED, m.state)
        assertTrue(actions.contains(Action.Revoke))
        assertTrue(result(true, idle).isEmpty())
        assertEquals(State.REVOKED, m.state)
    }

    @Test
    fun `tx without rx revokes at once, and an S1 success never restores Protected`() {
        val rx = reachProtected()
        var tx = 0L
        run(22) { tx += 500; c(rx, tx) } // 11 s of tx growth with no rx
        assertEquals(State.REVOKED, m.state)
        assertTrue(actions.contains(Action.Revoke))
        val recovery = lastProbe()
        assertEquals(ProbeKind.RECOVERY, recovery.kind)
        result(true)
        assertEquals(State.REVOKED, m.state)
        run(10) { c(rx, tx) }
        assertEquals(State.REVOKED, m.state)
        assertEquals(1, actions.count { it == Action.Promote })
    }

    @Test
    fun `fresh rx invalidates an outstanding probe - its late failure changes nothing`() {
        val rx = reachProtected()
        run(120) { c(rx, 0) }
        val idle = lastProbe()
        sample(c(rx + 1, 0)) // rx advance while the probe is in flight
        assertTrue(actions.contains(Action.CancelProbe))
        assertEquals(State.PROTECTED, m.state)
        assertTrue(result(false, idle).isEmpty())
        assertEquals(State.PROTECTED, m.state)
    }

    @Test
    fun `results with a stale request id or epoch are ignored`() {
        val rx = reachProtected()
        run(120) { c(rx, 0) }
        val idle = lastProbe()
        assertTrue(m.onProbeResult(idle.requestId + 7, idle.epoch, false, now).isEmpty())
        assertTrue(m.onProbeResult(idle.requestId, idle.epoch + 1, false, now).isEmpty())
        assertEquals(State.SUSPECT, m.state)
    }

    @Test
    fun `idle probe failure revokes, the second consecutive failure tears down`() {
        val rx = reachProtected()
        run(120) { c(rx, 0) }
        result(false)
        assertEquals(State.REVOKED, m.state)
        sample(c(rx, 0)) // schedules the immediate retry
        val retry = lastProbe()
        assertEquals(ProbeKind.RECOVERY, retry.kind)
        result(false)
        assertEquals(State.TORN_DOWN, m.state)
        assertTrue(actions.last() is Action.Teardown)
    }

    @Test
    fun `recovery after revoke needs E-HIST and E-RX of the new epoch - old rx does not count`() {
        val rx = reachProtected()
        sample(TransportStats.Unavailable)
        assertEquals(State.REVOKED, m.state)
        val revokedEpoch = m.epoch
        result(true) // recovery probe answers: still REVOKED
        // One fresh advance right after the revoke is not enough (needs >= 2 over >= 10 s in this epoch).
        sample(c(rx, 1)); sample(c(rx + 900, 1))
        assertEquals(State.REVOKED, m.state)
        var r = rx + 900
        run(22) { r += 900; c(r, 1) }
        assertEquals(State.PROTECTED, m.state)
        assertEquals(revokedEpoch, m.epoch)
    }

    @Test
    fun `SIGCONT analogue - live counters and S1 success without rx do not restore`() {
        val rx = reachProtected()
        sample(TransportStats.Unavailable)
        result(true)
        run(60) { c(rx, 0) }
        assertEquals(State.REVOKED, m.state)
    }

    @Test
    fun `recovery probes are serialized and bounded, and the deadline is not moved by success`() {
        val rx = reachProtected()
        sample(TransportStats.Unavailable) // revoke + first recovery probe
        var inFlight = 1
        var maxInFlight = 1
        repeat(600) { // 300 s
            val before = probes().size
            sample(c(rx, 1))
            if (probes().size > before) { inFlight++; maxInFlight = maxOf(maxInFlight, inFlight) }
            if (inFlight > 0 && it % 4 == 3) { result(true); inFlight-- }
        }
        assertEquals(1, maxInFlight)
        assertTrue("at most ${Hysteria2DataPlaneMonitor.MAX_RECOVERY_PROBES} recovery probes", probes().size <= Hysteria2DataPlaneMonitor.MAX_RECOVERY_PROBES)
        assertEquals("last probe succeeded -> hold, no teardown", State.REVOKED, m.state)
        assertFalse(actions.any { it is Action.Teardown })
    }

    @Test
    fun `deadline with a failed last probe tears down - decided only after the in-flight probe completes`() {
        val rx = reachProtected()
        sample(TransportStats.Unavailable)
        result(true) // probe 1 ok -> next at +60 s
        run(121) { c(rx, 1) } // probe 2 starts 60 s after probe 1 answered
        assertEquals(2, probes().size)
        run(130) { c(rx, 1) } // past the 120 s deadline with probe 2 still in flight: no decision yet
        assertEquals(State.REVOKED, m.state)
        assertFalse(actions.any { it is Action.Teardown })
        result(false) // probe 2 fails (consecutive failures = 1)
        sample(c(rx, 1))
        assertEquals(State.TORN_DOWN, m.state)
    }

    @Test
    fun `Unavailable and Unsupported are distinct`() {
        sample(TransportStats.Unavailable)
        run(100) { TransportStats.Unavailable }
        assertEquals("Unavailable is transient - no teardown, still verifying", State.VERIFYING, m.state)
        assertFalse(m.finished)
        sample(TransportStats.Unsupported)
        assertEquals(State.UNVERIFIABLE, m.state)
        assertTrue(actions.last() == Action.Stop)
        assertFalse(actions.any { it is Action.Teardown })
        assertTrue("nothing more after UNVERIFIABLE", m.onSample(c(1, 1), now).isEmpty())
    }

    @Test
    fun `Unsupported after Protected revokes and stops without teardown`() {
        reachProtected()
        sample(TransportStats.Unsupported)
        assertTrue(actions.contains(Action.Revoke))
        assertEquals(State.UNVERIFIABLE, m.state)
        assertFalse(actions.any { it is Action.Teardown })
    }

    @Test
    fun `a revoke starts a new epoch whose first sample is a baseline`() {
        val rx = reachProtected()
        val epoch = m.epoch
        sample(TransportStats.Unavailable)
        assertEquals(epoch + 1, m.epoch)
        sample(c(rx + 10_000, 1)) // big jump right after the revoke: baseline, not an advance
        assertEquals(1, m.epochSamples.size)
    }
}
