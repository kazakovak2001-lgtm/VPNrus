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
        // PR #43 review fix - EVERY record* function must take zero raw String
        // parameters, with NO exceptions (recordManifestSourceSelected used to
        // take a raw String label and was exempted here; it now takes the
        // closed ManifestSourceKind enum - see DiagnosticTypes.kt). This is a
        // structural, reflection-based proof that the API surface itself
        // cannot be handed a raw secret, host, URL, or other free-text value
        // to embed - not merely a convention enforced by review.
        val recordMethods = SupportDiagnosticsRecorder::class.java.declaredMethods
            .filter { it.name.startsWith("record") }
        assertTrue("expected at least one record* function", recordMethods.isNotEmpty())
        recordMethods.forEach { method ->
            val stringParams = method.parameterTypes.count { it == String::class.java }
            assertEquals(
                "record function '${method.name}' takes $stringParams raw String params - every record* function must take zero",
                0,
                stringParams,
            )
        }
    }
}
