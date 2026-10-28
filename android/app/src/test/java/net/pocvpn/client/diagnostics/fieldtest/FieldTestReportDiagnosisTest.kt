package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The new report sections end to end: run diagnosis, network timeline and roll-up in the JSON and the text summary. */
class FieldTestReportDiagnosisTest {
    private fun report(runs: List<FieldTransportRun>, events: NetworkEventSnapshot?) = FieldTestReport(
        startedAtEpochMillis = 1_000,
        finishedAtEpochMillis = 9_000,
        cancelled = false,
        abortReason = null,
        app = JSONObject(),
        device = JSONObject(),
        networkContextBefore = JSONObject(),
        networkContextAfter = null,
        appStateBefore = JSONObject(),
        appStateAfter = null,
        direct = null,
        runs = runs,
        supportBundle = null,
        networkEvents = events,
    )

    private fun failedRun(startedAt: Long, outcome: FieldRunOutcome) =
        FieldTransportRun(target = FieldAttemptTarget(null, null), startedAtEpochMillis = startedAt, outcome = outcome)

    private fun lost(at: Long) = NetworkEvent(at, at - 1_000, NetworkEventType.LOST, "100", listOf("CELLULAR"), null, null, null, null, null)

    @Test fun json_has_per_run_diagnosis_timeline_and_rollup() {
        val events = NetworkEventSnapshot(listOf(lost(2_500)), dropped = 0, registrationError = null)
        val json = report(
            listOf(failedRun(2_000, FieldRunOutcome.HANDSHAKE_FAILED), failedRun(5_000, FieldRunOutcome.HANDSHAKE_FAILED)),
            events,
        ).toJson()

        val runs = json.getJSONArray("runs")
        // The loss at 2 500 falls in the first attempt's window only.
        assertEquals("NETWORK_UNAVAILABLE", runs.getJSONObject(0).getJSONObject("diagnosis").getString("category"))
        assertEquals("HANDSHAKE_FAILED", runs.getJSONObject(1).getJSONObject("diagnosis").getString("category"))

        assertEquals(1, json.getJSONObject("networkEvents").getJSONArray("events").length())
        val summary = json.getJSONObject("diagnosisSummary")
        assertEquals(2, summary.getInt("attempts"))
        assertEquals("RECORDED", summary.getString("networkTimeline"))
        assertEquals(1, summary.getInt("underlyingNetworkLost"))
        assertEquals(1, summary.getJSONObject("byCategory").getInt("HANDSHAKE_FAILED"))
    }

    @Test fun without_a_timeline_the_report_says_so_instead_of_reporting_zero() {
        val json = report(listOf(failedRun(2_000, FieldRunOutcome.CONNECT_TIMEOUT)), null).toJson()
        val summary = json.getJSONObject("diagnosisSummary")
        assertEquals("NOT_PROVIDED", summary.getString("networkTimeline"))
        assertTrue(summary.isNull("underlyingNetworkLost"))
        assertTrue(!json.has("networkEvents"))
        // No timeline: a timeout stays a low-confidence, non-blocking hypothesis.
        val d = json.getJSONArray("runs").getJSONObject(0).getJSONObject("diagnosis")
        assertEquals("ENDPOINT_UNREACHABLE", d.getString("category"))
        assertEquals("LOW", d.getString("confidence"))
    }

    @Test fun failed_registration_is_unavailable_not_recorded() {
        val events = NetworkEventSnapshot(emptyList(), 0, "SecurityException")
        val json = report(listOf(failedRun(2_000, FieldRunOutcome.HANDSHAKE_FAILED)), events).toJson()
        assertEquals("UNAVAILABLE", json.getJSONObject("diagnosisSummary").getString("networkTimeline"))
        assertTrue(json.getJSONObject("diagnosisSummary").getInt("underlyingNetworkLost") == 0)
        // A broken timeline must not be used to explain the failure.
        val d = json.getJSONArray("runs").getJSONObject(0).getJSONObject("diagnosis")
        assertEquals("HANDSHAKE_FAILED", d.getString("category"))
    }

    @Test fun text_summary_shows_diagnosis_and_network_events() {
        val events = NetworkEventSnapshot(listOf(lost(2_500)), 0, null)
        val lines = report(listOf(failedRun(2_000, FieldRunOutcome.HANDSHAKE_FAILED)), events).summaryLines()
        assertTrue(lines.any { it.trim().startsWith("diagnosis: NETWORK_UNAVAILABLE (medium)") })
        assertTrue(lines.any { it.startsWith("Network events: 1, underlying lost 1") })
    }
}
