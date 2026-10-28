package net.pocvpn.client.diagnostics.fieldtest

import org.json.JSONArray
import org.json.JSONObject

/**
 * Root-cause hypothesis for ONE field-test attempt, derived only from what the
 * attempt measured (pure and unit-tested). It is a hypothesis with evidence
 * and a confidence, never a verdict: in particular a timeout alone is never
 * called operator blocking, and a missing measurement is listed as missing,
 * never read as a pass or as zero.
 */
enum class DiagnosisCategory {
    /** Tunnel up and the data plane verified. */
    OK,

    /** Android reported no usable underlying network, or it was lost during the attempt. */
    NETWORK_UNAVAILABLE,

    /** No connection was established in time. Does NOT by itself prove blocking. */
    ENDPOINT_UNREACHABLE,

    /** The handshake did not complete. */
    HANDSHAKE_FAILED,

    /** Tunnel reported up but test traffic did not pass. */
    TUNNEL_UP_DATA_PLANE_FAILED,

    /** IP-literal traffic works but name resolution failed. */
    DNS_FAILED,

    /** The observed exit or a leak check does not match the expected routing. */
    ROUTING_OR_LEAK_SUSPECTED,

    /** Small probes answered but the bulk transfer did not complete. */
    DATA_PLANE_DEGRADED,

    /** A flow froze after a few KB - the throttling pattern; a suspicion, not proof. */
    THROTTLING_SUSPECTED,

    /** The available measurements do not determine a cause. */
    INCONCLUSIVE,
}

enum class DiagnosisConfidence { LOW, MEDIUM, HIGH }

data class RunDiagnosis(
    val category: DiagnosisCategory,
    val confidence: DiagnosisConfidence,
    /** null = not applicable / not measured. */
    val tunnelEstablished: Boolean?,
    val dataPlaneVerified: Boolean?,
    val dnsVerified: Boolean?,
    val exitIpVerified: Boolean?,
    val evidence: List<String>,
    val missingMeasurements: List<String>,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("category", category.name)
        .put("confidence", confidence.name)
        .put("tunnelEstablished", tunnelEstablished ?: JSONObject.NULL)
        .put("dataPlaneVerified", dataPlaneVerified ?: JSONObject.NULL)
        .put("dnsVerified", dnsVerified ?: JSONObject.NULL)
        .put("exitIpVerified", exitIpVerified ?: JSONObject.NULL)
        .put("evidence", JSONArray(evidence))
        .put("missingMeasurements", JSONArray(missingMeasurements))
}

private val NO_NETWORK_MARKERS = listOf("no underlying network", "network is unreachable", "no default network")
private val IPV4_LITERAL_HOST = Regex("""^https?://\d{1,3}(\.\d{1,3}){3}[:/]""")

/** [window] is the network timeline slice for this attempt, or null when no timeline exists. */
fun diagnoseRun(run: FieldTransportRun, window: NetworkWindow?): RunDiagnosis {
    val evidence = mutableListOf<String>()
    val missing = mutableListOf<String>()
    val lost = window?.underlyingLost ?: 0
    if (window?.unvalidatedSeen == true) evidence += "Android marked the default network as not validated during this attempt"

    val dnsVerified = run.dns?.ok
    val exitIpVerified = if (run.exitIp != null && run.expectedExitIps.isNotEmpty()) run.exitIp in run.expectedExitIps else null

    fun result(
        category: DiagnosisCategory,
        confidence: DiagnosisConfidence,
        tunnel: Boolean?,
        data: Boolean?,
    ) = RunDiagnosis(category, confidence, tunnel, data, dnsVerified, exitIpVerified, evidence.toList(), missing.toList())

    when (run.outcome) {
        FieldRunOutcome.SKIPPED, FieldRunOutcome.UNAVAILABLE -> {
            evidence += "attempt was not made: ${run.skipReason ?: run.errorMessage ?: "not available"}"
            return result(DiagnosisCategory.INCONCLUSIVE, DiagnosisConfidence.LOW, null, null)
        }
        FieldRunOutcome.HANDSHAKE_FAILED, FieldRunOutcome.CONNECT_FAILED, FieldRunOutcome.CONNECT_TIMEOUT -> {
            val text = listOfNotNull(run.terminalState, run.errorMessage).plus(run.notes).joinToString(" ").lowercase()
            missing += "mobile signal quality (not collected in this build)"
            return when {
                NO_NETWORK_MARKERS.any { it in text } -> {
                    evidence += "Android reported no usable underlying network"
                    result(DiagnosisCategory.NETWORK_UNAVAILABLE, DiagnosisConfidence.HIGH, false, false)
                }
                lost > 0 -> {
                    evidence += "the default network was lost $lost time(s) during this attempt"
                    result(DiagnosisCategory.NETWORK_UNAVAILABLE, DiagnosisConfidence.MEDIUM, false, false)
                }
                run.outcome == FieldRunOutcome.HANDSHAKE_FAILED -> {
                    evidence += "the network was available but the handshake did not complete"
                    run.terminalState?.let { evidence += "terminal state: $it" }
                    missing += "independent reachability probe of the endpoint (separates a blocked endpoint from a failed handshake)"
                    result(DiagnosisCategory.HANDSHAKE_FAILED, DiagnosisConfidence.MEDIUM, false, false)
                }
                run.outcome == FieldRunOutcome.CONNECT_TIMEOUT -> {
                    evidence += "no connection within ${run.connectMs?.let { "${it} ms" } ?: "the time limit"}"
                    evidence += "a timeout alone does not prove blocking by the operator"
                    missing += "independent reachability probe of the endpoint"
                    result(DiagnosisCategory.ENDPOINT_UNREACHABLE, DiagnosisConfidence.LOW, false, false)
                }
                else -> {
                    run.errorMessage?.let { evidence += "error: $it" }
                    missing += "failure stage (DNS, socket or handshake) for this attempt"
                    result(DiagnosisCategory.INCONCLUSIVE, DiagnosisConfidence.LOW, false, false)
                }
            }
        }
        else -> Unit
    }

    // From here the tunnel reported Connected.
    val leaks = run.leaks
    val leakSuspected = leaks != null && (leaks.optBoolean("dnsLeakSuspected") || leaks.optBoolean("ipv6EgressWhileConnected"))
    if (lost > 0) evidence += "the default network was lost $lost time(s) during this attempt"

    val base: RunDiagnosis = when (run.outcome) {
        FieldRunOutcome.DATA_PLANE_OK -> {
            evidence += "probes answered and the bulk download completed"
            result(DiagnosisCategory.OK, DiagnosisConfidence.HIGH, true, true)
        }
        FieldRunOutcome.DATA_PLANE_CORE_CONFIRMED -> {
            evidence += "the Xray core reached targets through the tunnel (latency only)"
            missing += "bulk transfer, exit address and leak checks (the app is outside this tunnel)"
            result(DiagnosisCategory.OK, DiagnosisConfidence.MEDIUM, true, true)
        }
        FieldRunOutcome.CONNECTED_APP_EXCLUDED -> {
            evidence += "the transport confirmed the tunnel but the app is excluded from it and cannot measure"
            missing += "a check from a browser or another app"
            result(DiagnosisCategory.INCONCLUSIVE, DiagnosisConfidence.MEDIUM, true, null)
        }
        FieldRunOutcome.MEASUREMENT_INVALIDATED -> {
            evidence += "probes could not be attributed to this session"
            result(DiagnosisCategory.INCONCLUSIVE, DiagnosisConfidence.LOW, true, null)
        }
        FieldRunOutcome.DATA_PLANE_DEGRADED -> {
            evidence += "small probes answered but the bulk download did not complete"
            result(DiagnosisCategory.DATA_PLANE_DEGRADED, DiagnosisConfidence.MEDIUM, true, true)
        }
        FieldRunOutcome.DATA_PLANE_STALL_SUSPECTED -> {
            val stalls = (run.probes + run.stability + listOfNotNull(run.throughput)).mapNotNull { it.stalledAtBytes }
            evidence += "a transfer froze after ${stalls.joinToString("/")} bytes - the pattern to watch for, not proof of throttling"
            missing += "the same test on another network or transport"
            result(DiagnosisCategory.THROTTLING_SUSPECTED, DiagnosisConfidence.LOW, true, true)
        }
        FieldRunOutcome.EXIT_MISMATCH -> {
            evidence += "traffic exited from an address that is not one of this gateway's expected exits"
            result(DiagnosisCategory.ROUTING_OR_LEAK_SUSPECTED, DiagnosisConfidence.HIGH, true, false)
        }
        FieldRunOutcome.CONNECTED_NO_DATA -> {
            val ipProbeOk = run.probes.any { it.ok && IPV4_LITERAL_HOST.containsMatchIn(it.url) }
            if (run.dns != null && !run.dns.ok && ipProbeOk) {
                evidence += "an IP-literal probe passed while name resolution failed"
                result(DiagnosisCategory.DNS_FAILED, DiagnosisConfidence.HIGH, true, true)
            } else {
                evidence += "the tunnel reported Connected but ${if (run.probes.isEmpty()) "no probe was sent" else "none of ${run.probes.size} probe(s) answered"}"
                if (run.dns != null && !run.dns.ok) missing += "an IP-literal probe (separates DNS from the data plane)"
                val sure = if (run.probes.isNotEmpty() && lost == 0) DiagnosisConfidence.HIGH else DiagnosisConfidence.MEDIUM
                result(DiagnosisCategory.TUNNEL_UP_DATA_PLANE_FAILED, sure, true, false)
            }
        }
        // Handled above.
        FieldRunOutcome.SKIPPED, FieldRunOutcome.UNAVAILABLE, FieldRunOutcome.HANDSHAKE_FAILED,
        FieldRunOutcome.CONNECT_FAILED, FieldRunOutcome.CONNECT_TIMEOUT,
        -> result(DiagnosisCategory.INCONCLUSIVE, DiagnosisConfidence.LOW, null, null)
    }

    if (leakSuspected && base.category != DiagnosisCategory.ROUTING_OR_LEAK_SUSPECTED) {
        val kinds = buildList {
            if (leaks?.optBoolean("dnsLeakSuspected") == true) add("DNS resolver outside the tunnel")
            if (leaks?.optBoolean("ipv6EgressWhileConnected") == true) add("IPv6 egress while connected")
        }
        return base.copy(
            category = DiagnosisCategory.ROUTING_OR_LEAK_SUSPECTED,
            confidence = DiagnosisConfidence.MEDIUM,
            evidence = base.evidence + "leak check: ${kinds.joinToString(" and ")}",
        )
    }
    return base
}

/** Per-attempt diagnoses of a report, each with the network events of its own time window. */
internal fun FieldTestReport.diagnoses(): List<RunDiagnosis> {
    val events = networkEvents?.events
    return runs.mapIndexed { i, run ->
        val window = if (networkEvents == null || networkEvents.registrationError != null) {
            null
        } else {
            val end = runs.getOrNull(i + 1)?.startedAtEpochMillis ?: finishedAtEpochMillis
            networkWindow(events.orEmpty(), run.startedAtEpochMillis, end)
        }
        diagnoseRun(run, window)
    }
}
