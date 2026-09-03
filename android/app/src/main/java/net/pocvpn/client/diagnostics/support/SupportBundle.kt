package net.pocvpn.client.diagnostics.support

import org.json.JSONArray
import org.json.JSONObject

/**
 * B29 (task H) - the deterministic export model. [schemaVersion] lets a
 * future slice change the shape without breaking a support workflow already
 * parsing an older bundle. [sessions] is already the SANITIZED view (see
 * [buildSupportBundle]) - this type carries nothing else.
 */
data class SupportBundle(
    val schemaVersion: Int,
    val appVersionName: String,
    val appVersionCode: Long,
    val generatedAtEpochMillis: Long,
    val sessions: List<DiagnosticSession>,
) {
    companion object {
        const val SCHEMA_VERSION = 1
    }
}

/**
 * B29 (task H) - THE ONE function that turns a store's retained sessions
 * into an exportable [SupportBundle]. Applies [DiagnosticSanitizer] to every
 * tag value of every event of every session (task E's defense-in-depth
 * pass - see that object's own docs for why this is a SECOND check, not the
 * only one) before anything is serialized - this is the real
 * "sanitizer/export boundary" the task requires: nothing reaches
 * [SupportBundle]/[SupportBundle.toJson] without going through this
 * function first.
 */
fun buildSupportBundle(
    sessions: List<DiagnosticSession>,
    appVersionName: String,
    appVersionCode: Long,
    nowEpochMillis: Long,
): SupportBundle {
    val sanitizedSessions = sessions.map { session ->
        session.copy(events = session.events.map { it.copy(tags = DiagnosticSanitizer.sanitizeTags(it.tags)) })
    }
    return SupportBundle(
        schemaVersion = SupportBundle.SCHEMA_VERSION,
        appVersionName = appVersionName,
        appVersionCode = appVersionCode,
        generatedAtEpochMillis = nowEpochMillis,
        sessions = sanitizedSessions,
    )
}

/**
 * B29 (task H) - deterministic JSON serialization: every object's keys are
 * written in a FIXED, explicit order (never relying on a map/JSONObject's
 * own iteration order, which [org.json.JSONObject] does not contractually
 * guarantee) and every list preserves its own already-deterministic
 * (chronological / most-recent-first) order - the SAME bundle content
 * always serializes to the SAME string, byte for byte.
 */
fun SupportBundle.toJson(): String {
    val root = JSONObject()
    root.put("schemaVersion", schemaVersion)
    root.put("appVersionName", appVersionName)
    root.put("appVersionCode", appVersionCode)
    root.put("generatedAtEpochMillis", generatedAtEpochMillis)
    val sessionsArray = JSONArray()
    sessions.forEach { sessionsArray.put(it.toJson()) }
    root.put("sessions", sessionsArray)
    return root.toString()
}

private fun DiagnosticSession.toJson(): JSONObject {
    val obj = JSONObject()
    obj.put("sessionId", sessionId)
    obj.put("startedAtEpochMillis", startedAtEpochMillis)
    obj.put("endedAtEpochMillis", endedAtEpochMillis?.let { it as Any } ?: JSONObject.NULL)
    obj.put("appVersionName", appVersionName)
    obj.put("appVersionCode", appVersionCode)
    obj.put("networkType", networkType.name)
    obj.put("networkValidatedInternet", networkValidatedInternet)
    obj.put("networkCaptivePortal", networkCaptivePortal)
    obj.put("networkIpv4Available", networkIpv4Available)
    obj.put("networkIpv6Available", networkIpv6Available)
    obj.put("networkFingerprintId", networkFingerprintId ?: JSONObject.NULL)
    obj.put("rawRestrictionClass", rawRestrictionClass.name)
    obj.put("stabilizedRestrictionClass", stabilizedRestrictionClass.name)
    obj.put("routingMode", routingMode.name)
    obj.put("gatewaySelectionMode", gatewaySelectionMode.name)
    obj.put("selectedPathKind", selectedPathKind.name)
    obj.put("selectedTransportKind", selectedTransportKind?.name ?: JSONObject.NULL)
    val eventsArray = JSONArray()
    events.forEach { eventsArray.put(it.toJson()) }
    obj.put("events", eventsArray)
    obj.put("outcome", outcome.name)
    obj.put("failureReason", failureReason?.name ?: JSONObject.NULL)
    return obj
}

private fun DiagnosticEvent.toJson(): JSONObject {
    val obj = JSONObject()
    obj.put("type", type.name)
    obj.put("atEpochMillis", atEpochMillis)
    val tagsObj = JSONObject()
    // Sorted by key - the closed tag-key vocabulary is small and stable, so
    // sorting costs nothing and removes any dependency on insertion order.
    tags.toSortedMap().forEach { (k, v) -> tagsObj.put(k, v) }
    obj.put("tags", tagsObj)
    return obj
}
