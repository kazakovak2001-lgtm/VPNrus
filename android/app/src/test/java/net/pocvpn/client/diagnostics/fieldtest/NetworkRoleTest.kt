package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkRoleTest {
    private var now = 0L
    private val log = NetworkEventLog({ now })

    private fun rec(type: NetworkEventType, id: String, transports: List<String>, validated: Boolean? = true) =
        log.record(type, id, transports, validated, true, true, null, 2)

    private fun roleOf(index: Int) = log.snapshot().events[index].role

    @Test fun lost_is_attributed_from_the_transports_the_same_id_was_seen_with() {
        log.begin()
        rec(NetworkEventType.AVAILABLE, "322", listOf("CELLULAR", "VPN"))
        rec(NetworkEventType.AVAILABLE, "311", listOf("CELLULAR"))
        rec(NetworkEventType.LOST, "322", emptyList(), null)
        rec(NetworkEventType.LOST, "311", emptyList(), null)
        assertEquals(NetworkRole.VPN, roleOf(0))
        assertEquals(NetworkRole.UNDERLYING, roleOf(1))
        assertEquals(NetworkRole.VPN, roleOf(2))
        assertEquals(NetworkRole.UNDERLYING, roleOf(3))
    }

    @Test fun lost_of_an_id_never_seen_with_a_transport_is_unknown_and_not_assumed_underlying() {
        log.begin()
        rec(NetworkEventType.LOST, "900", emptyList(), null)
        val snap = log.snapshot()
        assertEquals(NetworkRole.UNKNOWN, snap.events[0].role)
        assertEquals(0, snap.underlyingLost)
        assertEquals(1, snap.unknownLost)
    }

    @Test fun begin_forgets_the_roles_of_the_previous_run() {
        log.begin()
        rec(NetworkEventType.AVAILABLE, "5", listOf("WIFI", "VPN"))
        log.begin()
        rec(NetworkEventType.LOST, "5", emptyList(), null)
        assertEquals(NetworkRole.UNKNOWN, roleOf(0))
    }

    @Test fun the_window_counts_only_underlying_losses_and_reports_unattributed_ones_separately() {
        log.begin()
        now = 1_000
        rec(NetworkEventType.AVAILABLE, "10", listOf("WIFI"))
        rec(NetworkEventType.AVAILABLE, "11", listOf("WIFI", "VPN"))
        now = 1_500
        rec(NetworkEventType.LOST, "11", emptyList(), null) // tunnel teardown
        now = 1_600
        rec(NetworkEventType.LOST, "10", emptyList(), null) // the Wi-Fi really went away
        now = 1_700
        rec(NetworkEventType.LOST, "77", emptyList(), null) // never seen
        val w = networkWindow(log.snapshot().events, 1_200, 2_000)
        assertEquals(1, w.underlyingLost)
        assertEquals(1, w.unknownLost)
        assertEquals(2, w.changes) // the VPN LOST is not a change of the underlying network
    }

    @Test fun field_report_shape_ten_tunnel_teardowns_are_zero_underlying_losses() {
        // Report 1793168897968: Wi-Fi 310 and cellular 311 stay; tunnel networks 312..321 come and go.
        log.begin()
        rec(NetworkEventType.AVAILABLE, "310", listOf("WIFI"))
        rec(NetworkEventType.AVAILABLE, "311", listOf("CELLULAR"))
        for (id in 312..321) {
            now += 1_000
            rec(NetworkEventType.AVAILABLE, id.toString(), listOf("WIFI", "VPN"))
            now += 1_000
            rec(NetworkEventType.LOST, id.toString(), emptyList(), null)
        }
        val snap = log.snapshot()
        assertEquals(0, snap.underlyingLost)
        assertEquals(10, snap.vpnLost)
        assertEquals(0, snap.unknownLost)
        assertFalse(snap.unvalidatedSeen)
        assertEquals(0, networkWindow(snap.events, 0, Long.MAX_VALUE).underlyingLost)
    }

    @Test fun unvalidated_state_of_the_tunnel_network_is_not_an_underlying_problem() {
        log.begin()
        rec(NetworkEventType.AVAILABLE, "312", listOf("WIFI", "VPN"), validated = false) // a new VPN network starts unvalidated
        assertFalse(log.snapshot().unvalidatedSeen)
        rec(NetworkEventType.CAPABILITIES_CHANGED, "310", listOf("WIFI"), validated = false)
        assertTrue(log.snapshot().unvalidatedSeen)
    }

    // --- report output ----------------------------------------------------------------

    private fun report(events: NetworkEventSnapshot) = FieldTestReport(
        startedAtEpochMillis = 1_000, finishedAtEpochMillis = 9_000, cancelled = false, abortReason = null,
        app = JSONObject(), device = JSONObject(), networkContextBefore = JSONObject(), networkContextAfter = null,
        appStateBefore = JSONObject(), appStateAfter = null, direct = null, runs = emptyList(), supportBundle = null,
        networkEvents = events,
    )

    @Test fun the_json_roll_up_and_the_summary_separate_tunnel_underlying_and_unattributed_losses() {
        log.begin()
        rec(NetworkEventType.AVAILABLE, "310", listOf("WIFI"))
        rec(NetworkEventType.AVAILABLE, "312", listOf("WIFI", "VPN"))
        rec(NetworkEventType.LOST, "312", emptyList(), null)
        rec(NetworkEventType.LOST, "99", emptyList(), null)
        val r = report(log.snapshot())

        val s = r.toJson().getJSONObject("diagnosisSummary")
        assertEquals(0, s.getInt("underlyingNetworkLost"))
        assertEquals(1, s.getInt("vpnNetworkLost"))
        assertEquals(1, s.getInt("unknownNetworkLost"))

        val line = r.summaryLines().first { it.startsWith("Network events:") }
        assertTrue(line, "underlying lost 0" in line)
        assertTrue(line, "tunnel network lost 1 (own disconnects)" in line)
        assertTrue(line, "unattributed lost 1" in line)

        val events = r.toJson().getJSONObject("networkEvents").getJSONArray("events")
        assertEquals("VPN", events.getJSONObject(2).getString("role"))
        assertEquals("UNKNOWN", events.getJSONObject(3).getString("role"))
    }

    @Test fun an_unattributed_loss_is_evidence_but_never_makes_the_attempt_network_unavailable() {
        val run = FieldTransportRun(
            target = FieldAttemptTarget(null, null), startedAtEpochMillis = 1_000, outcome = FieldRunOutcome.CONNECT_FAILED,
            errorMessage = "connect failed",
        )
        val d = diagnoseRun(run, NetworkWindow(underlyingLost = 0, unvalidatedSeen = false, changes = 1, unknownLost = 2))
        assertFalse(d.category == DiagnosisCategory.NETWORK_UNAVAILABLE)
        assertTrue(d.evidence.any { "2 network loss event(s) could not be attributed" in it })
    }
}
