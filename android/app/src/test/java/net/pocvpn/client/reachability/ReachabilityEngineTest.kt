package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ReachabilityEngineTest {

    private val endpoint = EndpointDescriptor(
        EndpointId("gw"),
        setOf(EndpointRole.GATEWAY),
        "eu",
        "acme",
        transports = listOf(EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.1", 51820)),
    )

    private fun assess(
        health: TransportHealth = TransportHealth(),
        endpointSpecific: Boolean? = null,
        networkUsable: Boolean = true,
        now: Long = 1_000_000L,
        // Defaults to "fresh, observed at `now`" whenever endpointSpecific
        // is set - existing call sites in this file keep asserting the
        // same behavior as before the PR #24 freshness fix without having
        // to thread a timestamp through every single test. Staleness tests
        // below override this explicitly.
        endpointSpecificOutcomeMillis: Long? = if (endpointSpecific != null) now else null,
    ) = ReachabilityEngine.assess(
        endpoint = endpoint,
        transportKind = TransportKind.AMNEZIA_WG,
        networkUsable = networkUsable,
        transportHealth = health,
        endpointSpecificReachable = endpointSpecific,
        restrictionClass = RestrictionClass.UNKNOWN,
        nowEpochMillis = now,
        endpointSpecificOutcomeEpochMillis = endpointSpecificOutcomeMillis,
    )

    @Test
    fun `no evidence at all stays UNKNOWN`() {
        val result = assess(health = TransportHealth(state = TransportHealthState.UNKNOWN))
        assertEquals(ReachabilityState.UNKNOWN, result.state)
    }

    @Test
    fun `a known-reachable endpoint (fresh real probe success) is REACHABLE`() {
        val result = assess(endpointSpecific = true, health = TransportHealth(state = TransportHealthState.DEGRADED))
        assertEquals(ReachabilityState.REACHABLE, result.state)
    }

    @Test
    fun `a fresh endpoint-specific failure with transport not healthy elsewhere is UNREACHABLE`() {
        val result = assess(endpointSpecific = false, health = TransportHealth(state = TransportHealthState.DEGRADED))
        assertEquals(ReachabilityState.UNREACHABLE, result.state)
    }

    @Test
    fun `transport healthy overall but this endpoint's own fresh probe failed is DEGRADED, not REACHABLE`() {
        val result = assess(endpointSpecific = false, health = TransportHealth(state = TransportHealthState.HEALTHY))
        assertEquals(ReachabilityState.DEGRADED, result.state)
    }

    @Test
    fun `endpoint reachable but the transport itself is not supported at this endpoint is UNREACHABLE`() {
        val result = ReachabilityEngine.assess(
            endpoint = endpoint,
            transportKind = TransportKind.TLS_TCP, // endpoint only declares AMNEZIA_WG
            networkUsable = true,
            transportHealth = TransportHealth(state = TransportHealthState.HEALTHY),
            endpointSpecificReachable = true,
            restrictionClass = RestrictionClass.UNKNOWN,
            nowEpochMillis = 1_000_000L,
            endpointSpecificOutcomeEpochMillis = 1_000_000L,
        )
        assertEquals(ReachabilityState.UNREACHABLE, result.state)
    }

    @Test
    fun `no usable network is UNKNOWN, never UNREACHABLE`() {
        val result = assess(networkUsable = false, health = TransportHealth(state = TransportHealthState.UNREACHABLE))
        assertEquals(ReachabilityState.UNKNOWN, result.state)
    }

    @Test
    fun `stale transport health evidence (no endpoint-specific evidence) is downgraded to UNKNOWN`() {
        val staleHealth = TransportHealth(state = TransportHealthState.HEALTHY, lastProbeEpochMillis = 0L)
        val result = assess(health = staleHealth, now = ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS + 1)
        assertEquals(ReachabilityState.UNKNOWN, result.state)
    }

    @Test
    fun `fresh transport health evidence is trusted`() {
        val freshHealth = TransportHealth(state = TransportHealthState.HEALTHY, lastProbeEpochMillis = 999_000L)
        val result = assess(health = freshHealth, now = 1_000_000L)
        assertEquals(ReachabilityState.REACHABLE, result.state)
    }

    @Test
    fun `NOT_IMPLEMENTED transport health maps to UNREACHABLE`() {
        val result = assess(health = TransportHealth(state = TransportHealthState.NOT_IMPLEMENTED))
        assertEquals(ReachabilityState.UNREACHABLE, result.state)
    }

    // --- PR #24 audit fix: endpoint-specific evidence freshness ---

    @Test
    fun `a STALE endpoint-specific SUCCESS no longer makes the state REACHABLE - falls back to transport health instead`() {
        val now = ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS + 2_000_000L
        val staleOutcomeAt = now - ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS - 1
        // Transport health itself stays fresh and DEGRADED so the fallback
        // path (rule 5) is exercised deterministically, not rule 3's
        // separate transport-health staleness check.
        val health = TransportHealth(state = TransportHealthState.DEGRADED, lastProbeEpochMillis = now - 1_000L)
        val result = assess(health = health, endpointSpecific = true, now = now, endpointSpecificOutcomeMillis = staleOutcomeAt)
        assertEquals(ReachabilityState.DEGRADED, result.state) // NOT REACHABLE - the stale success no longer counts
        assertEquals(true, result.evidence.endpointSpecificReachable) // still truthfully reported as the raw observed value
        assertEquals(staleOutcomeAt.let { now - it }, result.evidence.endpointSpecificReachableAgeMillis)
    }

    @Test
    fun `a STALE endpoint-specific FAILURE no longer forces UNREACHABLE or DEGRADED - falls back to transport health instead`() {
        val now = ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS + 2_000_000L
        val staleOutcomeAt = now - ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS - 1
        val health = TransportHealth(state = TransportHealthState.HEALTHY, lastProbeEpochMillis = now - 1_000L)
        val result = assess(health = health, endpointSpecific = false, now = now, endpointSpecificOutcomeMillis = staleOutcomeAt)
        assertEquals(ReachabilityState.REACHABLE, result.state) // NOT UNREACHABLE/DEGRADED - the stale failure no longer counts
        assertEquals(false, result.evidence.endpointSpecificReachable)
    }

    @Test
    fun `endpoint-specific evidence exactly at the TTL boundary is still fresh`() {
        val now = 10_000_000L
        val outcomeAt = now - ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS // exactly at the boundary, inclusive
        val result = assess(endpointSpecific = true, health = TransportHealth(state = TransportHealthState.HEALTHY), now = now, endpointSpecificOutcomeMillis = outcomeAt)
        assertEquals(ReachabilityState.REACHABLE, result.state)
    }

    @Test
    fun `endpoint-specific evidence one millisecond past the TTL is stale`() {
        val now = 10_000_000L
        val outcomeAt = now - ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS - 1
        val health = TransportHealth(state = TransportHealthState.HEALTHY, lastProbeEpochMillis = now - 1_000L)
        val result = assess(endpointSpecific = false, health = health, now = now, endpointSpecificOutcomeMillis = outcomeAt)
        assertEquals(ReachabilityState.REACHABLE, result.state) // falls back to transport health (HEALTHY), not the stale failure
    }

    @Test
    fun `endpoint-specific evidence with NO timestamp is treated as stale - never trusted merely because it exists`() {
        val health = TransportHealth(state = TransportHealthState.DEGRADED, lastProbeEpochMillis = 999_000L)
        val result = assess(health = health, endpointSpecific = true, now = 1_000_000L, endpointSpecificOutcomeMillis = null)
        assertEquals(ReachabilityState.DEGRADED, result.state) // falls back to transport health, not the undated "true"
        assertNull(result.evidence.endpointSpecificReachableAgeMillis)
    }

    @Test
    fun `endpoint-specific evidence age is never borrowed from TransportHealth's own age`() {
        // TransportHealth was probed very recently (fresh), but the
        // endpoint-specific outcome itself is old - the two ages must be
        // computed and reported completely independently.
        val now = 10_000_000L
        val health = TransportHealth(state = TransportHealthState.HEALTHY, lastProbeEpochMillis = now - 100L)
        val oldEndpointOutcome = now - ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS - 1
        val result = assess(health = health, endpointSpecific = false, now = now, endpointSpecificOutcomeMillis = oldEndpointOutcome)
        assertEquals(100L, result.evidence.transportHealthAgeMillis)
        assertEquals(ReachabilityEngine.DEFAULT_STALE_AFTER_MILLIS + 1, result.evidence.endpointSpecificReachableAgeMillis)
        assertEquals(ReachabilityState.REACHABLE, result.state) // stale failure ignored, fresh HEALTHY transport wins
    }
}
