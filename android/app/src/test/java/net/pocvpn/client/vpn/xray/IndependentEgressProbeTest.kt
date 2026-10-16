@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.runBlocking
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.vpn.IndependentEgressProbeResult
import net.pocvpn.client.vpn.config.ProductionGatewayCatalog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B-WL7 M1 - the pure parts of the independent-egress probe: which host is
 * independent of the current gateway, and how replies and session changes
 * on either side of the `:xray` exchange decide the result.
 */
class IndependentEgressProbeTest {

    // --- target choice: never the gateway the session exits through ---

    @Test
    fun `each catalog gateway is probed through the OTHER one`() {
        assertEquals(listOf("16.170.208.231"), IndependentEgressTargets.forSession(EndpointId("frankfurt")))
        assertEquals(listOf("152.70.43.1"), IndependentEgressTargets.forSession(EndpointId("stockholm")))
    }

    @Test
    fun `an endpoint outside the catalog gets no target - independence cannot be shown`() {
        assertTrue(IndependentEgressTargets.forSession(EndpointId("private-gw")).isEmpty())
        assertTrue(IndependentEgressTargets.forSession(null).isEmpty())
    }

    @Test
    fun `the independence assumption holds for the catalog - distinct providers and addresses, IP literals only`() {
        val gateways = ProductionGatewayCatalog.all
        assertEquals(gateways.size, gateways.map { it.provider }.toSet().size)
        assertEquals(gateways.size, gateways.map { it.awg.endpointHost }.toSet().size)
        gateways.forEach { assertTrue(it.awg.endpointHost, IndependentEgressTargets.isIpv4Literal(it.awg.endpointHost)) }
    }

    @Test
    fun `select never returns the session's own server or relay exit, nor a DNS name`() {
        assertEquals("16.170.208.231", IndependentEgressTargets.select(listOf("152.70.43.1", "16.170.208.231"), "152.70.43.1", null))
        assertNull(IndependentEgressTargets.select(listOf("152.70.43.1"), "152.70.43.1", null))
        assertNull(IndependentEgressTargets.select(listOf("16.170.208.231"), "152.70.43.1", "16.170.208.231"))
        assertNull(IndependentEgressTargets.select(listOf("gw.example.org", "300.1.1.1"), "152.70.43.1", null))
        assertNull(IndependentEgressTargets.select(emptyList(), "152.70.43.1", null))
    }

    // --- reply correlation (main process receiver) ---

    @Test
    fun `a reply for another request is ignored, the matching one completes`() {
        val reply = EgressProbeReply(requestId = 7)

        assertFalse(reply.offer(6, "REACHED"))
        assertFalse(reply.result.isCompleted)
        assertTrue(reply.offer(7, "NOT_REACHED"))
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, reply.result.getCompleted())
    }

    @Test
    fun `a duplicate reply cannot change the first result`() {
        val reply = EgressProbeReply(requestId = 7)

        assertTrue(reply.offer(7, "NOT_REACHED"))
        assertFalse(reply.offer(7, "REACHED"))
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, reply.result.getCompleted())
    }

    @Test
    fun `a malformed or missing result counts as not reached`() {
        val garbled = EgressProbeReply(requestId = 1)
        garbled.offer(1, "reached")
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, garbled.result.getCompleted())

        val missing = EgressProbeReply(requestId = 2)
        missing.offer(2, null)
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, missing.result.getCompleted())
    }

    // --- caller decision (main process) ---

    @Test
    fun `the caller accepts REACHED only for the still-Started same session`() {
        assertEquals(IndependentEgressProbeResult.REACHED, IndependentEgressDecision.forCaller(IndependentEgressProbeResult.REACHED, stillStartedSameSession = true))
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, IndependentEgressDecision.forCaller(IndependentEgressProbeResult.REACHED, stillStartedSameSession = false))
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, IndependentEgressDecision.forCaller(null, stillStartedSameSession = true))
        assertEquals(IndependentEgressProbeResult.UNAVAILABLE, IndependentEgressDecision.forCaller(IndependentEgressProbeResult.UNAVAILABLE, stillStartedSameSession = true))
    }

    // --- service decision (:xray process) ---

    @Test
    fun `the service never probes for a session it is not running`() = runBlocking {
        var probes = 0
        val probe: suspend () -> IndependentEgressProbeResult = { probes++; IndependentEgressProbeResult.REACHED }

        // A restarted :xray process starts with session id 0.
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, IndependentEgressDecision.forService(5, { 0L }, { true }, probe))
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, IndependentEgressDecision.forService(5, { 5L }, { false }, probe))
        assertEquals(0, probes)
    }

    @Test
    fun `a session change while the probe runs is never confirmed`() = runBlocking {
        var current = 5L
        val result = IndependentEgressDecision.forService(5, { current }, { true }) {
            current = 6L // a new session (or a restart) took over mid-probe
            IndependentEgressProbeResult.REACHED
        }
        assertEquals(IndependentEgressProbeResult.NOT_REACHED, result)
    }

    @Test
    fun `an unchanged session gets the probe's own result`() = runBlocking {
        assertEquals(IndependentEgressProbeResult.REACHED, IndependentEgressDecision.forService(5, { 5L }, { true }) { IndependentEgressProbeResult.REACHED })
        assertEquals(IndependentEgressProbeResult.UNAVAILABLE, IndependentEgressDecision.forService(5, { 5L }, { true }) { IndependentEgressProbeResult.UNAVAILABLE })
    }
}
