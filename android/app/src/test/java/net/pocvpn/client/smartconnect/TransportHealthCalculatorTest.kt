package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportFailureCategory
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TransportHealthCalculatorTest {

    private fun outcome(
        transport: TransportKind = TransportKind.AMNEZIA_WG,
        result: ConnectionOutcomeResult,
        handshakeDurationMs: Long? = null,
        errorCategory: ConnectionErrorCategory = ConnectionErrorCategory.NONE,
        timestampEpochMillis: Long = 1_000L,
    ) = ConnectionOutcome(
        transport = transport,
        gatewayId = "gw-test",
        result = result,
        handshakeDurationMs = handshakeDurationMs,
        errorCategory = errorCategory,
        timestampEpochMillis = timestampEpochMillis,
    )

    @Test
    fun `no outcomes for this kind yields UNKNOWN`() {
        val health = TransportHealthCalculator.fromOutcomes(emptyList(), TransportKind.AMNEZIA_WG)
        assertEquals(TransportHealthState.UNKNOWN, health.state)
        assertEquals(0, health.consecutiveFailures)
        assertNull(health.lastProbeEpochMillis)
    }

    @Test
    fun `outcomes for a different kind are ignored`() {
        val outcomes = listOf(outcome(transport = TransportKind.XRAY_REALITY, result = ConnectionOutcomeResult.SUCCESS))
        val health = TransportHealthCalculator.fromOutcomes(outcomes, TransportKind.AMNEZIA_WG)
        assertEquals(TransportHealthState.UNKNOWN, health.state)
    }

    @Test
    fun `most recent SUCCESS yields HEALTHY with real latency`() {
        val outcomes = listOf(
            outcome(result = ConnectionOutcomeResult.FAILURE, timestampEpochMillis = 1_000L),
            outcome(result = ConnectionOutcomeResult.SUCCESS, handshakeDurationMs = 250L, timestampEpochMillis = 2_000L),
        )
        val health = TransportHealthCalculator.fromOutcomes(outcomes, TransportKind.AMNEZIA_WG)
        assertEquals(TransportHealthState.HEALTHY, health.state)
        assertEquals(250L, health.latencyMillis)
        assertEquals(2_000L, health.lastProbeEpochMillis)
        assertEquals(0, health.consecutiveFailures)
        assertEquals(TransportFailureCategory.NONE, health.failureCategory)
    }

    @Test
    fun `one recent FAILURE after a SUCCESS yields DEGRADED, not UNREACHABLE`() {
        val outcomes = listOf(
            outcome(result = ConnectionOutcomeResult.SUCCESS, timestampEpochMillis = 1_000L),
            outcome(result = ConnectionOutcomeResult.FAILURE, errorCategory = ConnectionErrorCategory.HANDSHAKE_TIMEOUT, timestampEpochMillis = 2_000L),
        )
        val health = TransportHealthCalculator.fromOutcomes(outcomes, TransportKind.AMNEZIA_WG)
        assertEquals(TransportHealthState.DEGRADED, health.state)
        assertEquals(1, health.consecutiveFailures)
        assertEquals(TransportFailureCategory.TIMEOUT, health.failureCategory)
        assertNull(health.latencyMillis)
    }

    @Test
    fun `two or more consecutive real failures yield UNREACHABLE`() {
        val outcomes = listOf(
            outcome(result = ConnectionOutcomeResult.SUCCESS, timestampEpochMillis = 1_000L),
            outcome(result = ConnectionOutcomeResult.FAILURE, errorCategory = ConnectionErrorCategory.RECONNECT_EXHAUSTED, timestampEpochMillis = 2_000L),
            outcome(result = ConnectionOutcomeResult.FAILURE, errorCategory = ConnectionErrorCategory.RECONNECT_EXHAUSTED, timestampEpochMillis = 3_000L),
        )
        val health = TransportHealthCalculator.fromOutcomes(outcomes, TransportKind.AMNEZIA_WG)
        assertEquals(TransportHealthState.UNREACHABLE, health.state)
        assertEquals(2, health.consecutiveFailures)
        assertEquals(TransportFailureCategory.HANDSHAKE_FAILED, health.failureCategory)
    }

    @Test
    fun `only the most recent unbroken run of failures counts as consecutive`() {
        val outcomes = listOf(
            outcome(result = ConnectionOutcomeResult.FAILURE, timestampEpochMillis = 1_000L),
            outcome(result = ConnectionOutcomeResult.FAILURE, timestampEpochMillis = 2_000L),
            outcome(result = ConnectionOutcomeResult.SUCCESS, timestampEpochMillis = 3_000L),
            outcome(result = ConnectionOutcomeResult.FAILURE, timestampEpochMillis = 4_000L),
        )
        val health = TransportHealthCalculator.fromOutcomes(outcomes, TransportKind.AMNEZIA_WG)
        assertEquals(1, health.consecutiveFailures)
        assertEquals(TransportHealthState.DEGRADED, health.state)
    }

    @Test
    fun `BACKEND_START_FAILURE and OTHER map to UNKNOWN failure category, never fabricated as HANDSHAKE_FAILED`() {
        val backendFailure = TransportHealthCalculator.fromOutcomes(
            listOf(outcome(result = ConnectionOutcomeResult.FAILURE, errorCategory = ConnectionErrorCategory.BACKEND_START_FAILURE)),
            TransportKind.AMNEZIA_WG,
        )
        assertEquals(TransportFailureCategory.UNKNOWN, backendFailure.failureCategory)

        val otherFailure = TransportHealthCalculator.fromOutcomes(
            listOf(outcome(result = ConnectionOutcomeResult.FAILURE, errorCategory = ConnectionErrorCategory.OTHER)),
            TransportKind.AMNEZIA_WG,
        )
        assertEquals(TransportFailureCategory.UNKNOWN, otherFailure.failureCategory)
    }
}
