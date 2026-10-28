package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RunDiagnosisTest {
    private val target = FieldAttemptTarget(gateway = null, transport = null)

    private fun run(
        outcome: FieldRunOutcome,
        terminalState: String? = null,
        errorMessage: String? = null,
        connectMs: Long? = null,
        dns: DnsProbeResult? = null,
        probes: List<HttpProbeResult> = emptyList(),
        exitIp: String? = null,
        expected: Set<String> = emptySet(),
        leaks: JSONObject? = null,
    ) = FieldTransportRun(
        target = target, startedAtEpochMillis = 1_000, outcome = outcome, terminalState = terminalState,
        errorMessage = errorMessage, connectMs = connectMs, dns = dns, probes = probes, exitIp = exitIp,
        expectedExitIps = expected, leaks = leaks,
    )

    private fun probe(url: String, ok: Boolean, stalledAt: Long? = null) = HttpProbeResult(
        label = "p", url = url, ok = ok, httpStatus = if (ok) 200 else null, elapsedMs = 10, timeToHeadersMs = null,
        bytesRead = 0, stalledAtBytes = stalledAt, bodyComplete = ok, error = if (ok) null else "fail",
    )

    private fun dns(ok: Boolean) = DnsProbeResult("h", ok, emptyList(), 5, if (ok) null else "nx")

    @Test fun data_plane_ok_is_ok_high_and_all_flags_true() {
        val d = diagnoseRun(run(FieldRunOutcome.DATA_PLANE_OK, dns = dns(true), exitIp = "1.1.1.1", expected = setOf("1.1.1.1")), null)
        assertEquals(DiagnosisCategory.OK, d.category)
        assertEquals(DiagnosisConfidence.HIGH, d.confidence)
        assertEquals(true, d.tunnelEstablished)
        assertEquals(true, d.dataPlaneVerified)
        assertEquals(true, d.dnsVerified)
        assertEquals(true, d.exitIpVerified)
    }

    @Test fun timeout_is_low_confidence_unreachable_and_never_claims_blocking() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECT_TIMEOUT, connectMs = 15_000), null)
        assertEquals(DiagnosisCategory.ENDPOINT_UNREACHABLE, d.category)
        assertEquals(DiagnosisConfidence.LOW, d.confidence)
        assertTrue(d.evidence.any { "does not prove blocking" in it })
        assertTrue(d.missingMeasurements.isNotEmpty())
        assertEquals(false, d.tunnelEstablished)
    }

    @Test fun handshake_failure_with_available_network() {
        val d = diagnoseRun(run(FieldRunOutcome.HANDSHAKE_FAILED, terminalState = "HandshakeFailed"), NetworkWindow(0, false, 0))
        assertEquals(DiagnosisCategory.HANDSHAKE_FAILED, d.category)
        assertEquals(DiagnosisConfidence.MEDIUM, d.confidence)
    }

    @Test fun no_underlying_network_text_wins_with_high_confidence() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECT_FAILED, errorMessage = "no underlying network"), null)
        assertEquals(DiagnosisCategory.NETWORK_UNAVAILABLE, d.category)
        assertEquals(DiagnosisConfidence.HIGH, d.confidence)
    }

    @Test fun network_lost_during_failed_attempt_is_network_unavailable_medium() {
        val d = diagnoseRun(run(FieldRunOutcome.HANDSHAKE_FAILED), NetworkWindow(underlyingLost = 2, unvalidatedSeen = false, changes = 3))
        assertEquals(DiagnosisCategory.NETWORK_UNAVAILABLE, d.category)
        assertEquals(DiagnosisConfidence.MEDIUM, d.confidence)
    }

    @Test fun unvalidated_network_is_recorded_as_evidence_only() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECT_TIMEOUT), NetworkWindow(0, true, 1))
        assertEquals(DiagnosisCategory.ENDPOINT_UNREACHABLE, d.category)
        assertTrue(d.evidence.any { "not validated" in it })
    }

    @Test fun connected_no_data_with_probes_is_data_plane_failed_high() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECTED_NO_DATA, probes = listOf(probe("https://a.example/", false))), null)
        assertEquals(DiagnosisCategory.TUNNEL_UP_DATA_PLANE_FAILED, d.category)
        assertEquals(DiagnosisConfidence.HIGH, d.confidence)
        assertEquals(true, d.tunnelEstablished)
        assertEquals(false, d.dataPlaneVerified)
    }

    @Test fun connected_no_data_after_a_network_loss_is_not_overstated() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECTED_NO_DATA), NetworkWindow(1, false, 1))
        assertEquals(DiagnosisConfidence.MEDIUM, d.confidence)
    }

    @Test fun ip_literal_probe_ok_with_dns_failed_is_dns_failed() {
        val d = diagnoseRun(
            run(FieldRunOutcome.CONNECTED_NO_DATA, dns = dns(false), probes = listOf(probe("https://1.1.1.1/x", true), probe("https://a.example/", false))),
            null,
        )
        assertEquals(DiagnosisCategory.DNS_FAILED, d.category)
        assertEquals(false, d.dnsVerified)
    }

    @Test fun dns_failed_without_an_ip_probe_asks_for_one() {
        val d = diagnoseRun(run(FieldRunOutcome.CONNECTED_NO_DATA, dns = dns(false), probes = listOf(probe("https://a.example/", false))), null)
        assertEquals(DiagnosisCategory.TUNNEL_UP_DATA_PLANE_FAILED, d.category)
        assertTrue(d.missingMeasurements.any { "IP-literal" in it })
    }

    @Test fun exit_mismatch_is_routing_suspected_and_exit_unverified() {
        val d = diagnoseRun(run(FieldRunOutcome.EXIT_MISMATCH, exitIp = "9.9.9.9", expected = setOf("1.1.1.1")), null)
        assertEquals(DiagnosisCategory.ROUTING_OR_LEAK_SUSPECTED, d.category)
        assertEquals(false, d.exitIpVerified)
        assertFalse(d.evidence.any { "9.9.9.9" in it })
    }

    @Test fun leak_check_downgrades_an_otherwise_ok_run() {
        val leaks = JSONObject().put("dnsLeakSuspected", true).put("ipv6EgressWhileConnected", false)
        val d = diagnoseRun(run(FieldRunOutcome.DATA_PLANE_OK, leaks = leaks), null)
        assertEquals(DiagnosisCategory.ROUTING_OR_LEAK_SUSPECTED, d.category)
        assertEquals(DiagnosisConfidence.MEDIUM, d.confidence)
        assertTrue(d.evidence.any { "DNS resolver outside the tunnel" in it })
    }

    @Test fun stall_is_only_a_suspicion() {
        val d = diagnoseRun(run(FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED, probes = listOf(probe("https://a/", true, stalledAt = 20_000))), null)
        assertEquals(DiagnosisCategory.THROTTLING_SUSPECTED, d.category)
        assertEquals(DiagnosisConfidence.LOW, d.confidence)
        assertTrue(d.evidence.any { "not proof" in it })
    }

    @Test fun app_excluded_and_invalidated_are_inconclusive_with_unknown_data_plane() {
        val excluded = diagnoseRun(run(FieldRunOutcome.CONNECTED_APP_EXCLUDED), null)
        assertEquals(DiagnosisCategory.INCONCLUSIVE, excluded.category)
        assertNull(excluded.dataPlaneVerified)
        assertEquals(true, excluded.tunnelEstablished)
        val invalid = diagnoseRun(run(FieldRunOutcome.MEASUREMENT_INVALIDATED), null)
        assertEquals(DiagnosisCategory.INCONCLUSIVE, invalid.category)
        assertNull(invalid.dataPlaneVerified)
    }

    @Test fun skipped_and_unavailable_are_not_failures() {
        val d = diagnoseRun(run(FieldRunOutcome.UNAVAILABLE, errorMessage = "no profile"), null)
        assertEquals(DiagnosisCategory.INCONCLUSIVE, d.category)
        assertNull(d.tunnelEstablished)
    }

    @Test fun missing_dns_and_exit_stay_null_not_false() {
        val d = diagnoseRun(run(FieldRunOutcome.DATA_PLANE_OK), null)
        assertNull(d.dnsVerified)
        assertNull(d.exitIpVerified)
    }

    // --- network timeline ---------------------------------------------------

    private var now = 10_000L

    @Test fun log_records_relative_time_and_bounds_capacity() {
        val log = NetworkEventLog({ now }, capacity = 2)
        log.begin()
        now = 10_500
        log.record(NetworkEventType.AVAILABLE, "100", listOf("CELLULAR"), true, true, true, "rmnet0", 2)
        now = 11_000
        log.record(NetworkEventType.LOST, "100", listOf("CELLULAR"), null, null, null, null, null)
        log.record(NetworkEventType.AVAILABLE, "101", listOf("WIFI"), true, true, true, "wlan0", 1)
        val snap = log.snapshot()
        assertEquals(2, snap.events.size)
        assertEquals(1, snap.dropped)
        assertEquals(500L, snap.events[0].tRelMs)
        assertEquals(1_000L, snap.events[1].tRelMs)
        assertNull(snap.events[1].validated)
    }

    @Test fun window_counts_only_underlying_events_in_range() {
        val events = listOf(
            NetworkEvent(900, 0, NetworkEventType.LOST, "1", listOf("CELLULAR"), null, null, null, null, null),
            NetworkEvent(1_100, 0, NetworkEventType.LOST, "1", listOf("CELLULAR"), null, null, null, null, null),
            NetworkEvent(1_200, 0, NetworkEventType.CAPABILITIES_CHANGED, "1", listOf("CELLULAR"), false, true, null, null, null),
            NetworkEvent(1_300, 0, NetworkEventType.LOST, "2", listOf("VPN"), null, null, null, null, null),
            NetworkEvent(2_000, 0, NetworkEventType.LOST, "1", listOf("CELLULAR"), null, null, null, null, null),
        )
        val w = networkWindow(events, 1_000, 2_000)
        assertEquals(1, w.underlyingLost)
        assertTrue(w.unvalidatedSeen)
        assertEquals(2, w.changes)
    }

    @Test fun failed_registration_is_reported_not_treated_as_no_changes() {
        val log = NetworkEventLog({ now })
        log.begin()
        log.failRegistration("SecurityException")
        assertEquals("SecurityException", log.snapshot().registrationError)
    }
}
