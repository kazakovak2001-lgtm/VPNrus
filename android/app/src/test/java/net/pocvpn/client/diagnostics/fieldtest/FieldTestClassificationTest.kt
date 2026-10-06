package net.pocvpn.client.diagnostics.fieldtest

import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Test

class FieldTestClassificationTest {

    private fun ok(status: Int = 200, bytes: Long = 100) = HttpProbeResult("p", "u", true, status, 10, 5, bytes, null, true, null)
    private fun stalled(at: Long) = HttpProbeResult("p", "u", false, 200, 9000, 5, at, at, false, "stalled")
    private fun failed() = HttpProbeResult("p", "u", false, null, 10, null, 0, null, false, "SocketTimeoutException")

    private fun classify(
        connected: Boolean = true,
        state: String? = "Connected",
        error: String? = null,
        timedOut: Boolean = false,
        probes: List<HttpProbeResult> = listOf(ok()),
        throughput: HttpProbeResult? = ok(bytes = 1_048_576),
        stability: List<HttpProbeResult> = emptyList(),
        exitIp: String? = "152.70.43.1",
        expected: Set<String> = setOf("152.70.43.1"),
    ) = classifyRun(connected, state, error, timedOut, probes, throughput, stability, exitIp, expected)

    @Test fun `connected with full download and matching exit is DATA_PLANE_OK`() =
        assertEquals(FieldRunOutcome.DATA_PLANE_OK, classify())

    @Test fun `incomplete bulk download is DEGRADED`() =
        assertEquals(FieldRunOutcome.DATA_PLANE_DEGRADED, classify(throughput = failed()))

    @Test fun `freeze inside 8-64 KB wins over everything else`() {
        assertEquals(FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED, classify(throughput = stalled(16_384)))
        assertEquals(FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED, classify(stability = listOf(stalled(20_000)), exitIp = "9.9.9.9"))
    }

    @Test fun `a stall outside the suspect range is only DEGRADED`() =
        assertEquals(FieldRunOutcome.DATA_PLANE_DEGRADED, classify(throughput = stalled(700_000)))

    @Test fun `exit through another address is EXIT_MISMATCH`() =
        assertEquals(FieldRunOutcome.EXIT_MISMATCH, classify(exitIp = "16.170.208.231"))

    @Test fun `connected but nothing answered is CONNECTED_NO_DATA`() =
        assertEquals(FieldRunOutcome.CONNECTED_NO_DATA, classify(probes = listOf(failed()), throughput = failed(), exitIp = null))

    @Test fun `refused attempts are UNAVAILABLE`() {
        assertEquals(FieldRunOutcome.UNAVAILABLE, classify(connected = false, state = "Disconnected", error = "NoCandidateAvailable"))
        assertEquals(FieldRunOutcome.UNAVAILABLE, classify(connected = false, state = "Disconnected", error = "UnsupportedTransportSelected: HYSTERIA2"))
    }

    @Test fun `handshake failure, timeout and generic error are distinguished`() {
        assertEquals(FieldRunOutcome.HANDSHAKE_FAILED, classify(connected = false, state = "HandshakeFailed"))
        assertEquals(FieldRunOutcome.CONNECT_TIMEOUT, classify(connected = false, state = "Connecting", timedOut = true))
        assertEquals(FieldRunOutcome.CONNECT_FAILED, classify(connected = false, state = "Error(message=x)", error = "x"))
    }

    @Test fun `trace body parses key value lines`() =
        assertEquals(mapOf("ip" to "1.2.3.4", "loc" to "RU", "colo" to "ARN"), parseTraceBody("fl=\nip=1.2.3.4\nloc=RU\ncolo=ARN\n\nbad line").filterKeys { it != "fl" })

    @Test fun `plan is every gateway x transport then smart connect`() {
        val plan = planAttempts(ProductionGatewayId.entries.toList())
        assertEquals(ProductionGatewayId.entries.size * FIELD_TEST_TRANSPORTS.size + 1, plan.size)
        assertEquals(FieldAttemptTarget(null, null), plan.last())
    }
}
