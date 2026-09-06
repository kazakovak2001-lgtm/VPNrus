package net.pocvpn.client.fieldtest

import net.pocvpn.client.diagnostics.support.DiagnosticEvent
import net.pocvpn.client.diagnostics.support.DiagnosticEventType
import net.pocvpn.client.diagnostics.support.DiagnosticSanitizer
import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.ProductionGatewayId
import net.pocvpn.client.vpn.policy.RoutingMode
import org.json.JSONArray
import org.json.JSONObject

/**
 * Russia field-test build (FIELD_TEST_ONLY) - sanitized, typed event tags.
 * Reuses the EXISTING [DiagnosticEvent]/[DiagnosticEventType] vocabulary,
 * never a second, independently-shaped event type - same discipline as
 * [net.pocvpn.client.bootstrap.BootstrapDiagnosticTags]. Every tag value is
 * an enum name or a small closed literal - NEVER a private key, activation
 * credential, raw VPN profile, device secret, UUID/token, payload, or
 * destination URL (the exact list this task forbids).
 */
object FieldTestDiagnosticTags {
    const val TAG_CANDIDATE = "candidate"
    const val TAG_TRANSPORT_KIND = "transport_kind"
    const val TAG_SUCCESS = "success"
    const val TAG_ATTEMPTED_COUNT = "attempted_count"
    const val TAG_STAGE = "stage"
    /** B37 - distinguishes this run's actual AWG generation. Never a private detail: just an enum name, see [AwgGeneration]. */
    const val TAG_AWG_GENERATION = "awg_generation"
    /** B37 - the gateway's own public endpoint host, exactly as already committed non-secret in the gateway catalogs (same posture as the gateway's own public key). */
    const val TAG_ENDPOINT_HOST = "endpoint_host"
    /** B37 - the UDP port attempted (51820 production `awg0`, 51821 isolated `awg-ft31`) - lets a report distinguish which server-side interface was actually reached. */
    const val TAG_ENDPOINT_PORT = "endpoint_port"
    /** B37 - the bounded handshake-wait window this attempt used, in milliseconds (task requirement: diagnostics must be able to distinguish a real timeout from a fake instant success). */
    const val TAG_HANDSHAKE_TIMEOUT_MS = "handshake_timeout_ms"
}

/**
 * B37 - which AmneziaWG parameter generation this field-test run actually
 * negotiated with. [AWG_3_1] is the ONLY generation [FieldTestTunnelController]
 * exercises as of B37 (see [FieldTestAwg31GatewayCatalog]) - [AWG_LEGACY] is
 * kept only as a closed, named alternative so a serialized report's
 * [FieldTestDiagnosticTags.TAG_AWG_GENERATION] value is self-describing
 * (task requirement A: "FIELD_TEST_ONLY really selects AWG 3.1, not
 * legacy AWG" - a report that could only ever say one thing would not
 * actually prove this).
 */
enum class AwgGeneration { AWG_LEGACY, AWG_3_1 }

/**
 * The closed, sanitized failure taxonomy this field test can report -
 * mirrors [net.pocvpn.client.diagnostics.support.DiagnosticFailureReason]'s
 * own discipline but scoped to exactly what this small flow can observe.
 */
enum class FieldTestFailureCategory {
    /**
     * The Android VPN permission dialog was shown and the user denied it (or
     * dismissed it without granting). Device/app-level, not gateway-specific
     * - this is reached BEFORE the Frankfurt/Stockholm candidate loop ever
     * starts, so it is never confused with an actual AWG/network failure on
     * either gateway (the real-device incident this category fixes).
     */
    VPN_PERMISSION_DENIED,
    /** Transport connect() threw, or no fresh AWG handshake was observed within the bounded window. */
    NO_HANDSHAKE,
    /** A fresh handshake was observed, but the post-handshake health/data-plane check failed. */
    HEALTH_CHECK_FAILED,
    /** Every known candidate failed. */
    ALL_CANDIDATES_EXHAUSTED,
    NONE,
}

/**
 * The bounded, in-memory sink for field-test [DiagnosticEvent]s - mirrors
 * [net.pocvpn.client.bootstrap.BootstrapDiagnosticsRecorder] exactly (same
 * "no activation/RestrictionClassifier pipeline exists ahead of this flow"
 * reasoning - see that class's own docs).
 */
class FieldTestDiagnosticsRecorder(
    private val nowProvider: () -> Long = System::currentTimeMillis,
) {
    private val events = mutableListOf<DiagnosticEvent>()

    @Synchronized
    private fun record(type: DiagnosticEventType, tags: Map<String, String> = emptyMap()) {
        events += DiagnosticEvent(type = type, atEpochMillis = nowProvider(), tags = tags)
        while (events.size > MAX_EVENTS) events.removeAt(0)
    }

    /**
     * The Android VPN permission dialog is about to be shown - always
     * recorded BEFORE the Frankfurt/Stockholm candidate loop starts, and
     * always followed by exactly one of [recordPermissionGranted]/
     * [recordPermissionDenied] before any [recordAttemptStarted] - see
     * [FieldTestViewModel.ensureVpnPermission]'s own docs for why permission
     * is device/app-level, checked ONCE, never per-candidate.
     */
    fun recordPermissionRequested() = record(DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_REQUESTED)

    fun recordPermissionGranted() = record(DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_GRANTED)

    fun recordPermissionDenied() = record(DiagnosticEventType.FIELD_TEST_VPN_PERMISSION_DENIED)

    fun recordAttemptStarted(
        candidate: ProductionGatewayId,
        transportKind: TransportKind,
        awgGeneration: AwgGeneration,
        endpointHost: String,
        endpointPort: Int,
        handshakeTimeoutMs: Long,
    ) {
        record(
            DiagnosticEventType.FIELD_TEST_ATTEMPT_STARTED,
            mapOf(
                FieldTestDiagnosticTags.TAG_CANDIDATE to candidate.name,
                FieldTestDiagnosticTags.TAG_TRANSPORT_KIND to transportKind.name,
                FieldTestDiagnosticTags.TAG_AWG_GENERATION to awgGeneration.name,
                FieldTestDiagnosticTags.TAG_ENDPOINT_HOST to endpointHost,
                FieldTestDiagnosticTags.TAG_ENDPOINT_PORT to endpointPort.toString(),
                FieldTestDiagnosticTags.TAG_HANDSHAKE_TIMEOUT_MS to handshakeTimeoutMs.toString(),
            ),
        )
    }

    fun recordCandidateResult(candidate: ProductionGatewayId, handshakeSuccess: Boolean) {
        record(
            DiagnosticEventType.FIELD_TEST_CANDIDATE_RESULT,
            mapOf(
                FieldTestDiagnosticTags.TAG_CANDIDATE to candidate.name,
                FieldTestDiagnosticTags.TAG_SUCCESS to handshakeSuccess.toString(),
            ),
        )
    }

    /** B37 (task C4) - a local transport startup/config error was detected right after connect(), distinct from a genuine handshake timeout - see [FieldTestTunnelController]'s own docs. */
    fun recordTransportError(candidate: ProductionGatewayId) {
        record(
            DiagnosticEventType.FIELD_TEST_TRANSPORT_ERROR,
            mapOf(FieldTestDiagnosticTags.TAG_CANDIDATE to candidate.name),
        )
    }

    fun recordHealthResult(candidate: ProductionGatewayId, healthy: Boolean) {
        record(
            DiagnosticEventType.FIELD_TEST_HEALTH_RESULT,
            mapOf(
                FieldTestDiagnosticTags.TAG_CANDIDATE to candidate.name,
                FieldTestDiagnosticTags.TAG_SUCCESS to healthy.toString(),
            ),
        )
    }

    fun recordBecameProtected(candidate: ProductionGatewayId) {
        record(DiagnosticEventType.FIELD_TEST_BECAME_PROTECTED, mapOf(FieldTestDiagnosticTags.TAG_CANDIDATE to candidate.name))
    }

    fun recordUnavailable(attempted: List<ProductionGatewayId>) {
        record(
            DiagnosticEventType.FIELD_TEST_UNAVAILABLE,
            mapOf(FieldTestDiagnosticTags.TAG_ATTEMPTED_COUNT to attempted.size.toString()),
        )
    }

    fun recordReportUploadAttempted() = record(DiagnosticEventType.FIELD_TEST_REPORT_UPLOAD_ATTEMPTED)

    fun recordReportUploadResult(success: Boolean) =
        record(DiagnosticEventType.FIELD_TEST_REPORT_UPLOAD_RESULT, mapOf(FieldTestDiagnosticTags.TAG_SUCCESS to success.toString()))

    @Synchronized
    fun snapshot(): List<DiagnosticEvent> = events.toList()

    private companion object {
        const val MAX_EVENTS = 200
    }
}

/**
 * One complete field-test run's sanitized report - everything requirement 2
 * of the task asks for, nothing requirement 3 forbids. Deliberately a
 * SEPARATE type from [net.pocvpn.client.diagnostics.support.DiagnosticSession]
 * (that type requires a live [net.pocvpn.client.smartconnect.RestrictionClassifier]/
 * routing-policy snapshot this standalone build does not have wired the same
 * way) - reuses that model's field NAMES/shapes and the same
 * [DiagnosticEvent] vocabulary so a human/tool already familiar with a
 * normal support bundle can read this one just as easily.
 *
 * [buildLabel] MUST always identify this as FIELD_TEST_ONLY (requirement 6)
 * - see [FieldTestBuildInfo].
 */
data class FieldTestReport(
    val buildLabel: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val generatedAtEpochMillis: Long,
    val networkType: NetworkType,
    val routingMode: RoutingMode,
    val restrictionClass: RestrictionClass,
    val gatewaysAttempted: List<ProductionGatewayId>,
    val finalGateway: ProductionGatewayId?,
    val finalTransportKind: TransportKind?,
    /** B37 - which AmneziaWG parameter generation this run actually attempted (task requirement: a report must be able to distinguish AWG_3_1 from AWG_LEGACY, not merely say "AmneziaWG"). */
    val awgGeneration: AwgGeneration,
    val outcome: FieldTestOutcome,
    val failureCategory: FieldTestFailureCategory,
    val events: List<DiagnosticEvent>,
) {
    companion object {
        const val SCHEMA_VERSION = 1
    }
}

enum class FieldTestOutcome { PROTECTED, FAILED }

/**
 * Defense-in-depth pass (task's own "no secrets in serialized diagnostic
 * output" test) - reuses [DiagnosticSanitizer], the SAME second check
 * [net.pocvpn.client.diagnostics.support.buildSupportBundle] already applies
 * to every event tag before serialization, never a second/independent
 * sanitizer implementation.
 */
fun FieldTestReport.sanitizedForExport(): FieldTestReport =
    copy(events = events.map { it.copy(tags = DiagnosticSanitizer.sanitizeTags(it.tags)) })

fun FieldTestReport.toJson(): String {
    val root = JSONObject()
    root.put("schemaVersion", FieldTestReport.SCHEMA_VERSION)
    root.put("buildLabel", buildLabel)
    root.put("appVersionName", appVersionName)
    root.put("appVersionCode", appVersionCode)
    root.put("generatedAtEpochMillis", generatedAtEpochMillis)
    root.put("networkType", networkType.name)
    root.put("routingMode", routingMode.name)
    root.put("restrictionClass", restrictionClass.name)
    val attemptedArray = JSONArray()
    gatewaysAttempted.forEach { attemptedArray.put(it.name) }
    root.put("gatewaysAttempted", attemptedArray)
    root.put("finalGateway", finalGateway?.name ?: JSONObject.NULL)
    root.put("finalTransportKind", finalTransportKind?.name ?: JSONObject.NULL)
    root.put("awgGeneration", awgGeneration.name)
    root.put("outcome", outcome.name)
    root.put("failureCategory", failureCategory.name)
    val eventsArray = JSONArray()
    events.forEach { eventsArray.put(it.toFieldTestJson()) }
    root.put("events", eventsArray)
    return root.toString()
}

private fun DiagnosticEvent.toFieldTestJson(): JSONObject {
    val obj = JSONObject()
    obj.put("type", type.name)
    obj.put("atEpochMillis", atEpochMillis)
    val tagsObj = JSONObject()
    tags.toSortedMap().forEach { (k, v) -> tagsObj.put(k, v) }
    obj.put("tags", tagsObj)
    return obj
}

/** Marks every field-test artifact (report, UI, logs) unambiguously - requirement 6. */
object FieldTestBuildInfo {
    const val BUILD_LABEL: String = "FIELD_TEST_ONLY"
}

/**
 * Delivers a finished [FieldTestReport] somewhere the tester/operator can
 * read it. [uploadThroughTunnel] is attempted ONLY after the VPN tunnel is
 * genuinely [FieldTestState.Protected] (requirement 4) and its failure MUST
 * NEVER tear down or fail an otherwise healthy VPN session (requirement 5) -
 * callers always treat its result as informational only.
 *
 * No production diagnostics-upload endpoint exists in this codebase today
 * (verified: no existing report/upload API) - see [NoOpFieldTestReportUploader],
 * the real production wiring, for why this interface currently always falls
 * back to the existing local export/share mechanism ([FieldTestActivity]'s
 * "Share report" action, reusing the exact same
 * `Intent.ACTION_SEND`/`text/json` pattern [net.pocvpn.client.ui.AppRoot]'s
 * own "Export diagnostics" button already uses) rather than fabricate a
 * fake success against a server that does not exist.
 */
interface FieldTestReportUploader {
    suspend fun uploadThroughTunnel(report: FieldTestReport): Boolean
}

/**
 * Real production wiring - see [FieldTestReportUploader]'s own docs for why
 * this always returns false (no server endpoint exists to upload to). Doing
 * so is what correctly drives requirement 4's own fallback: "if automatic
 * upload cannot work, keep the report locally and preserve the existing
 * export/share mechanism".
 */
object NoOpFieldTestReportUploader : FieldTestReportUploader {
    override suspend fun uploadThroughTunnel(report: FieldTestReport): Boolean = false
}
