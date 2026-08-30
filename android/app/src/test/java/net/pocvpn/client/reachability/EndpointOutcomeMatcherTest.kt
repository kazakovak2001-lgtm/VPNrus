package net.pocvpn.client.reachability

import net.pocvpn.client.smartconnect.ConnectionErrorCategory
import net.pocvpn.client.smartconnect.ConnectionOutcome
import net.pocvpn.client.smartconnect.ConnectionOutcomeResult
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EndpointOutcomeMatcherTest {

    private fun outcome(
        gatewayId: String,
        transport: TransportKind,
        result: ConnectionOutcomeResult,
        timestampEpochMillis: Long,
    ) = ConnectionOutcome(
        transport = transport,
        gatewayId = gatewayId,
        result = result,
        handshakeDurationMs = null,
        errorCategory = ConnectionErrorCategory.NONE,
        timestampEpochMillis = timestampEpochMillis,
    )

    @Test
    fun `the newest matching outcome wins, regardless of list order`() {
        val outcomes = listOf(
            outcome("gw", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.SUCCESS, timestampEpochMillis = 3_000L),
            outcome("gw", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.FAILURE, timestampEpochMillis = 5_000L),
            outcome("gw", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.SUCCESS, timestampEpochMillis = 1_000L),
        )
        val latest = EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw"), TransportKind.AMNEZIA_WG)
        assertEquals(5_000L, latest!!.timestampEpochMillis)
        assertEquals(ConnectionOutcomeResult.FAILURE, latest.result)
    }

    @Test
    fun `an outcome for a different endpoint never matches`() {
        val outcomes = listOf(outcome("other-gateway", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.SUCCESS, 1_000L))
        assertNull(EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw"), TransportKind.AMNEZIA_WG))
    }

    @Test
    fun `an outcome for a different transport never matches`() {
        val outcomes = listOf(outcome("gw", TransportKind.TLS_TCP, ConnectionOutcomeResult.SUCCESS, 1_000L))
        assertNull(EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw"), TransportKind.AMNEZIA_WG))
    }

    @Test
    fun `evidence for multiple endpoints and transports never leaks across keys`() {
        val outcomes = listOf(
            outcome("gw-a", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.SUCCESS, 1_000L),
            outcome("gw-a", TransportKind.TLS_TCP, ConnectionOutcomeResult.FAILURE, 2_000L),
            outcome("gw-b", TransportKind.AMNEZIA_WG, ConnectionOutcomeResult.FAILURE, 3_000L),
        )
        assertEquals(ConnectionOutcomeResult.SUCCESS, EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw-a"), TransportKind.AMNEZIA_WG)!!.result)
        assertEquals(ConnectionOutcomeResult.FAILURE, EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw-a"), TransportKind.TLS_TCP)!!.result)
        assertEquals(ConnectionOutcomeResult.FAILURE, EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw-b"), TransportKind.AMNEZIA_WG)!!.result)
        assertNull(EndpointOutcomeMatcher.latestMatching(outcomes, EndpointId("gw-b"), TransportKind.TLS_TCP))
    }

    @Test
    fun `no outcomes at all returns null`() {
        assertNull(EndpointOutcomeMatcher.latestMatching(emptyList(), EndpointId("gw"), TransportKind.AMNEZIA_WG))
    }
}
