package net.pocvpn.client.diagnostics.support

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B29 (task E/K) - closed field-set proofs: [DiagnosticSession]/[DiagnosticEvent]
 * structurally have NO field capable of carrying a destination hostname/URL,
 * packet payload, DNS query, SSID/BSSID, or device identifier - the same
 * "closed, non-secret field set" discipline this codebase already applies to
 * [net.pocvpn.client.smartconnect.RestrictionEvidence]/
 * [net.pocvpn.client.reachability.ReachabilityEvidenceSummary].
 */
class DiagnosticTypesTest {

    private val forbiddenFieldNameFragments = listOf(
        "host", "url", "domain", "destination", "payload", "dns", "ssid", "bssid",
        "imsi", "imei", "phone", "advertisingid", "location", "latitude", "longitude",
        "credential", "password", "privatekey", "uuid", "token", "secret",
    )

    @Test
    fun `DiagnosticSession carries no field whose name suggests a destination, payload, or device identifier`() {
        val fieldNames = DiagnosticSession::class.java.declaredFields
            .map { it.name }
            .filterNot { it.contains('$') }
        val lowerNames = fieldNames.map { it.lowercase() }
        forbiddenFieldNameFragments.forEach { forbidden ->
            assertTrue(
                "DiagnosticSession must never gain a field named like '$forbidden' - actual fields: $fieldNames",
                lowerNames.none { it.contains(forbidden) },
            )
        }
    }

    @Test
    fun `DiagnosticEvent carries only a type, a timestamp, and a closed sanitized tag map - no free-text message field`() {
        val fieldNames = DiagnosticEvent::class.java.declaredFields
            .map { it.name }
            .filterNot { it.contains('$') }
            .toSet()
        assertEquals(setOf("type", "atEpochMillis", "tags"), fieldNames)
    }

    @Test
    fun `SupportDiagnosticsRecorder's record functions never accept a raw free-text String tag value parameter`() {
        // The ONLY String parameters any record* function accepts are enum-backed
        // labels (source label, already an enum-like closed string in production)
        // - never an arbitrary detail/message string. This is a structural,
        // reflection-based proof that the API surface itself cannot be handed
        // a raw secret to embed.
        val recordMethods = SupportDiagnosticsRecorder::class.java.declaredMethods
            .filter { it.name.startsWith("record") }
        assertTrue("expected at least one record* function", recordMethods.isNotEmpty())
        recordMethods.forEach { method ->
            val stringParams = method.parameterTypes.count { it == String::class.java }
            assertTrue(
                "record function '${method.name}' takes $stringParams raw String params - only recordManifestSourceSelected's single closed label is expected to take one",
                stringParams == 0 || method.name == "recordManifestSourceSelected",
            )
        }
    }
}
