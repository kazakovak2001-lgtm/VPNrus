package net.pocvpn.client.debug

import net.pocvpn.client.vpn.IndependentEgressProbeResult
import net.pocvpn.client.vpn.xray.XrayRuntimeEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL7 M1 debug hook - the pure gate only. Says nothing about real egress,
 * TLS at runtime or whether either gateway is reachable.
 */
class EgressProbeHookGateTest {

    private val target = listOf("16.170.208.231")

    @Test
    fun `refuses without a Connected Started session, while in flight, or without a target`() {
        val started = XrayRuntimeEvent.Started(7)
        assertTrue(EgressProbeHookGate.preflight(false, false, started, target) is EgressProbeHookGate.Preflight.Refused)
        assertTrue(EgressProbeHookGate.preflight(true, true, started, target) is EgressProbeHookGate.Preflight.Refused)
        assertTrue(EgressProbeHookGate.preflight(true, false, XrayRuntimeEvent.Stopped(7), target) is EgressProbeHookGate.Preflight.Refused)
        assertTrue(EgressProbeHookGate.preflight(true, false, null, target) is EgressProbeHookGate.Preflight.Refused)
        assertTrue(EgressProbeHookGate.preflight(true, false, started, emptyList()) is EgressProbeHookGate.Preflight.Refused)
        assertEquals(EgressProbeHookGate.Preflight.Ready(7, "16.170.208.231"), EgressProbeHookGate.preflight(true, false, started, target))
    }

    @Test
    fun `a REACHED from a session that stopped or was replaced is never reported as REACHED`() {
        val reached = IndependentEgressProbeResult.REACHED
        assertEquals(EgressProbeHookGate.Outcome.STALE_SESSION, EgressProbeHookGate.classify(7, XrayRuntimeEvent.Started(8), reached, null))
        assertEquals(EgressProbeHookGate.Outcome.STALE_SESSION, EgressProbeHookGate.classify(7, XrayRuntimeEvent.Stopped(7), reached, null))
        assertEquals(EgressProbeHookGate.Outcome.STALE_SESSION, EgressProbeHookGate.classify(7, null, reached, null))
        assertEquals(EgressProbeHookGate.Outcome.REACHED, EgressProbeHookGate.classify(7, XrayRuntimeEvent.Started(7), reached, null))
    }

    @Test
    fun `only a REACHED result is attributed to a session id`() {
        assertEquals("session=7", EgressProbeHookGate.sessionLabel(7, EgressProbeHookGate.Outcome.REACHED))
        EgressProbeHookGate.Outcome.entries.filter { it != EgressProbeHookGate.Outcome.REACHED }.forEach {
            assertEquals("session=unattributed coreSessionAtStart=7", EgressProbeHookGate.sessionLabel(7, it))
        }
        // A screen-owned older session probed while the core runs a newer one: the bridge answers NOT_REACHED.
        val outcome = EgressProbeHookGate.classify(8, XrayRuntimeEvent.Started(8), IndependentEgressProbeResult.NOT_REACHED, null)
        assertEquals(EgressProbeHookGate.Outcome.NOT_REACHED, outcome)
        assertEquals("session=unattributed coreSessionAtStart=8", EgressProbeHookGate.sessionLabel(8, outcome))
    }

    @Test
    fun `timeout and errors are distinct outcomes, never REACHED`() {
        val same = XrayRuntimeEvent.Started(7)
        assertEquals(EgressProbeHookGate.Outcome.TIMEOUT, EgressProbeHookGate.classify(7, same, null, null))
        assertEquals(EgressProbeHookGate.Outcome.ERROR, EgressProbeHookGate.classify(7, same, IndependentEgressProbeResult.REACHED, IllegalStateException()))
        assertEquals(EgressProbeHookGate.Outcome.NOT_REACHED, EgressProbeHookGate.classify(7, same, IndependentEgressProbeResult.NOT_REACHED, null))
        assertEquals(EgressProbeHookGate.Outcome.UNAVAILABLE, EgressProbeHookGate.classify(7, same, IndependentEgressProbeResult.UNAVAILABLE, null))
    }
}
