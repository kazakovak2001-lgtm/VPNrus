package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ThroughputVerdictTest {
    private fun probe(
        ok: Boolean = true,
        status: Int? = 200,
        elapsedMs: Long = 1_288,
        bytes: Long = 1_048_576,
        stalledAt: Long? = null,
        complete: Boolean = ok,
        kind: ProbeFailureKind? = null,
        transferMs: Long? = null,
    ) = HttpProbeResult(
        label = "Bulk 1MB", url = "https://speed.example/", ok = ok, httpStatus = status, elapsedMs = elapsedMs,
        timeToHeadersMs = null, bytesRead = bytes, stalledAtBytes = stalledAt, bodyComplete = complete,
        error = if (ok) null else "x", failureKind = kind, transferMs = transferMs,
    )

    private fun reason(v: ThroughputVerdict) = (v as ThroughputVerdict.NotMeasured).reason

    @Test fun a_complete_2xx_body_in_a_valid_session_is_measured_in_kbit_per_s() {
        val v = throughputVerdict(probe(transferMs = 1_288), sessionInvalidated = false) as ThroughputVerdict.Measured
        assertEquals(6_512L, v.rateKbps) // 1 048 576 B * 8 / 1 288 ms
        assertEquals(1_288L, v.transferMs)
        assertEquals(1_048_576L, v.bytes)
    }

    @Test fun the_rate_uses_the_first_to_last_byte_window_not_the_total_time() {
        val v = throughputVerdict(probe(elapsedMs = 4_000, transferMs = 1_000), false) as ThroughputVerdict.Measured
        assertEquals(8_388L, v.rateKbps) // 1 048 576 * 8 / 1 000
        assertEquals(1_000L, v.transferMs)
    }

    @Test fun an_older_result_without_a_transfer_window_falls_back_to_the_total_time() {
        val v = throughputVerdict(probe(elapsedMs = 2_000, transferMs = null), false) as ThroughputVerdict.Measured
        assertEquals(2_000L, v.transferMs)
    }

    @Test fun a_zero_transfer_window_never_divides_by_zero() {
        val v = throughputVerdict(probe(bytes = 1_000, transferMs = 0), false) as ThroughputVerdict.Measured
        assertEquals(1L, v.transferMs)
        assertEquals(8_000L, v.rateKbps)
    }

    @Test fun an_invalidated_session_is_never_measured_even_if_the_probe_looks_fine() {
        assertEquals(ThroughputNotMeasuredReason.SESSION_INVALIDATED, reason(throughputVerdict(probe(), sessionInvalidated = true)))
    }

    @Test fun the_field_report_case_a_failed_lookup_in_a_dead_tunnel_is_not_0_kbit() {
        // Report 1793168897968, STOCKHOLM / AMNEZIA_WG: 0 bytes, 12 031 ms, UnknownHostException.
        val dead = probe(ok = false, status = null, elapsedMs = 12_031, bytes = 0, kind = ProbeFailureKind.UNKNOWN_HOST)
        assertEquals(ThroughputNotMeasuredReason.DNS_FAILED, reason(throughputVerdict(dead, sessionInvalidated = false)))
        assertEquals(ThroughputNotMeasuredReason.SESSION_INVALIDATED, reason(throughputVerdict(dead, sessionInvalidated = true)))
    }

    @Test fun failures_before_a_body_are_classified_by_exception_type() {
        fun fail(kind: ProbeFailureKind?) = reason(throughputVerdict(probe(ok = false, status = null, bytes = 0, kind = kind), false))
        assertEquals(ThroughputNotMeasuredReason.TLS_FAILED, fail(ProbeFailureKind.TLS))
        assertEquals(ThroughputNotMeasuredReason.NO_RESPONSE, fail(ProbeFailureKind.TIMEOUT))
        assertEquals(ThroughputNotMeasuredReason.CONNECT_FAILED, fail(ProbeFailureKind.NO_ROUTE))
        assertEquals(ThroughputNotMeasuredReason.CONNECT_FAILED, fail(ProbeFailureKind.OTHER))
        assertEquals(ThroughputNotMeasuredReason.NO_RESPONSE, fail(null))
    }

    @Test fun a_non_2xx_status_is_an_http_error_not_a_rate() {
        assertEquals(ThroughputNotMeasuredReason.HTTP_ERROR, reason(throughputVerdict(probe(ok = true, status = 503, bytes = 512), false)))
    }

    @Test fun a_stall_reports_where_it_stopped_and_no_average() {
        val v = throughputVerdict(probe(ok = false, bytes = 16_384, stalledAt = 16_384, complete = false, elapsedMs = 9_000), false)
        val n = v as ThroughputVerdict.NotMeasured
        assertEquals(ThroughputNotMeasuredReason.STALLED, n.reason)
        assertEquals(16_384L, n.stalledAtBytes)
        assertEquals(16_384L, n.bytesRead)
    }

    @Test fun an_exhausted_time_budget_is_a_timeout_not_a_rate() {
        assertEquals(ThroughputNotMeasuredReason.TIMEOUT, reason(throughputVerdict(probe(ok = false, bytes = 300_000, complete = false), false)))
    }

    @Test fun an_empty_2xx_body_is_no_response() {
        assertEquals(ThroughputNotMeasuredReason.NO_RESPONSE, reason(throughputVerdict(probe(bytes = 0), false)))
    }

    // --- report output ----------------------------------------------------------------

    private fun report(vararg runs: FieldTransportRun) = FieldTestReport(
        startedAtEpochMillis = 1_000, finishedAtEpochMillis = 9_000, cancelled = false, abortReason = null,
        app = JSONObject(), device = JSONObject(), networkContextBefore = JSONObject(), networkContextAfter = null,
        appStateBefore = JSONObject(), appStateAfter = null, direct = null, runs = runs.toList(), supportBundle = null,
    )

    private fun run(outcome: FieldRunOutcome, throughput: HttpProbeResult) = FieldTransportRun(
        target = FieldAttemptTarget(null, null), startedAtEpochMillis = 2_000, outcome = outcome, throughput = throughput,
    )

    @Test fun the_summary_of_an_invalidated_run_has_no_bulk_figure() {
        val dead = probe(ok = false, status = null, elapsedMs = 12_031, bytes = 0, kind = ProbeFailureKind.UNKNOWN_HOST)
        val lines = report(run(FieldRunOutcome.MEASUREMENT_INVALIDATED, dead)).summaryLines()
        assertFalse(lines.any { "kbit" in it })
        assertFalse(lines.any { "bulk" in it })
    }

    @Test fun the_summary_of_a_valid_run_shows_the_measured_rate() {
        val lines = report(run(FieldRunOutcome.DATA_PLANE_OK, probe(transferMs = 1_288))).summaryLines()
        assertTrue(lines.any { "bulk 1024KB/1288ms (~6512kbit/s)" in it })
    }

    @Test fun the_summary_of_a_degraded_run_says_not_measured_with_the_reason() {
        val stalled = probe(ok = false, bytes = 16_384, stalledAt = 16_384, complete = false)
        val lines = report(run(FieldRunOutcome.DATA_PLANE_DEGRADED, stalled)).summaryLines()
        assertTrue(lines.any { "bulk not measured (STALLED, 16384B read, stalled at 16384B)" in it })
        assertFalse(lines.any { "kbit" in it })
    }

    @Test fun json_of_an_invalidated_run_is_not_valid_and_has_no_rate() {
        val dead = probe(ok = false, status = null, elapsedMs = 12_031, bytes = 0, kind = ProbeFailureKind.UNKNOWN_HOST)
        val t = report(run(FieldRunOutcome.MEASUREMENT_INVALIDATED, dead)).toJson()
            .getJSONArray("runs").getJSONObject(0).getJSONObject("throughput")
        assertEquals(false, t.getBoolean("valid"))
        assertEquals("SESSION_INVALIDATED", t.getString("invalidReason"))
        assertTrue(t.isNull("rateKbps"))
        assertEquals(12_031L, t.getLong("totalMs"))
        assertEquals(12_031L, t.getLong("elapsedMs")) // legacy field kept
    }

    @Test fun json_of_a_valid_run_carries_the_rate_and_the_transfer_window() {
        val t = report(run(FieldRunOutcome.DATA_PLANE_OK, probe(elapsedMs = 2_000, transferMs = 1_288))).toJson()
            .getJSONArray("runs").getJSONObject(0).getJSONObject("throughput")
        assertEquals(true, t.getBoolean("valid"))
        assertEquals(6_512L, t.getLong("rateKbps"))
        assertEquals(1_288L, t.getLong("transferMs"))
        assertEquals(2_000L, t.getLong("totalMs"))
    }

    @Test fun the_schema_version_is_bumped_for_the_new_fields() {
        assertEquals(2, report().toJson().getInt("schemaVersion"))
    }
}
