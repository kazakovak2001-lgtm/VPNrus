package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
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
    ) = ReachabilityEngine.assess(
        endpoint = endpoint,
        transportKind = TransportKind.AMNEZIA_WG,
        networkUsable = networkUsable,
        transportHealth = health,
        endpointSpecificReachable = endpointSpecific,
        restrictionClass = RestrictionClass.UNKNOWN,
        nowEpochMillis = now,
    )

    @Test
    fun `no evidence at all stays UNKNOWN`() {
        val result = assess(health = TransportHealth(state = TransportHealthState.UNKNOWN))
        assertEquals(ReachabilityState.UNKNOWN, result.state)
    }

    @Test
    fun `a known-reachable endpoint (real probe success) is REACHABLE`() {
        val result = assess(endpointSpecific = true, health = TransportHealth(state = TransportHealthState.DEGRADED))
        assertEquals(ReachabilityState.REACHABLE, result.state)
    }

    @Test
    fun `transport healthy overall but this endpoint's own probe failed is DEGRADED, not REACHABLE`() {
        val result = assess(endpointSpecific = false, health = TransportHealth(state = TransportHealthState.HEALTHY))
        assertEquals(ReachabilityState.DEGRADED, result.state)
    }

    @Test
    fun `endpoint probe failed and transport is not healthy elsewhere is UNREACHABLE`() {
        val result = assess(endpointSpecific = false, health = TransportHealth(state = TransportHealthState.DEGRADED))
        assertEquals(ReachabilityState.UNREACHABLE, result.state)
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
}
