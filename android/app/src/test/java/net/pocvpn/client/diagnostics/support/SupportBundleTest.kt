package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B29 (task H/K) - buildSupportBundle()/toJson(): sanitization pass, deterministic/bounded serialization, no secrets survive export. */
class SupportBundleTest {

    private fun sessionWithTag(secretTagValue: String) = DiagnosticSession(
        sessionId = "11111111-1111-1111-1111-111111111111",
        startedAtEpochMillis = 1_000L,
        endedAtEpochMillis = 2_000L,
        appVersionName = "1.0",
        appVersionCode = 1L,
        networkType = NetworkType.WIFI,
        networkValidatedInternet = true,
        networkCaptivePortal = false,
        networkIpv4Available = true,
        networkIpv6Available = false,
        networkFingerprintId = "fingerprint123",
        rawRestrictionClass = RestrictionClass.POSSIBLE_HARD_WHITELIST,
        stabilizedRestrictionClass = RestrictionClass.POSSIBLE_HARD_WHITELIST,
        routingMode = RoutingMode.FULL_VPN,
        gatewaySelectionMode = GatewaySelectionMode.AUTO,
        selectedPathKind = PathKind.CHAIN_CDN,
        selectedTransportKind = TransportKind.TLS_TCP,
        events = listOf(
            DiagnosticEvent(DiagnosticEventType.PATH_FAILED, 1_500L, mapOf("leaked" to secretTagValue, "failureReason" to "RELAY_END_TO_END_PROOF_FAILED")),
        ),
        outcome = DiagnosticOutcome.FAILED,
        failureReason = DiagnosticFailureReason.RELAY_END_TO_END_PROOF_FAILED,
    )

    @Test
    fun `buildSupportBundle sanitizes secret-shaped tag values before export`() {
        val secret = "Authorization: Bearer sk_live_SECRETTOKEN1234567890"
        val bundle = buildSupportBundle(listOf(sessionWithTag(secret)), "1.0", 1L, nowEpochMillis = 5_000L)
        val json = bundle.toJson()
        assertFalse(json.contains("SECRETTOKEN"))
        assertFalse(json.contains("Bearer"))
        assertTrue(json.contains("[redacted]"))
    }

    @Test
    fun `a security test - deliberately secret sentinel strings never appear anywhere in the exported bundle`() {
        val sentinels = listOf(
            "2f6b9e2a-3c1d-4e5f-8a9b-1234567890ab", // UUID-shaped credential/tunnel identity
            "hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y=", // AWG/REALITY-shaped private key
            "Bearer sk_live_SECRETBEARERTOKEN000", // auth header
            "-----BEGIN PRIVATE KEY-----MIIBSECRET-----END PRIVATE KEY-----", // PEM block
            "https://gateway.example.net/v1/activate?token=SECRETQUERYVALUE", // URL with secret query data
            "203.0.113.55", // endpoint IP
        )
        val sessions = sentinels.mapIndexed { i, sentinel ->
            sessionWithTag(sentinel).copy(sessionId = "session-$i")
        }
        val bundle = buildSupportBundle(sessions, "1.0", 1L, nowEpochMillis = 5_000L)
        val json = bundle.toJson()
        sentinels.forEach { sentinel ->
            assertFalse("sentinel '$sentinel' must never appear in the exported bundle", json.contains(sentinel))
        }
    }

    @Test
    fun `serialization is deterministic - the same bundle content always produces the same JSON string`() {
        val bundle = buildSupportBundle(listOf(sessionWithTag("safe-value")), "1.0", 1L, nowEpochMillis = 5_000L)
        val a = bundle.toJson()
        val b = bundle.toJson()
        assertEquals(a, b)
    }

    @Test
    fun `the exported JSON round-trips the non-secret, closed-vocabulary fields`() {
        val bundle = buildSupportBundle(listOf(sessionWithTag("safe-value")), "1.0", 1L, nowEpochMillis = 5_000L)
        val root = JSONObject(bundle.toJson())
        assertEquals(SupportBundle.SCHEMA_VERSION, root.getInt("schemaVersion"))
        assertEquals("1.0", root.getString("appVersionName"))
        assertEquals(5_000L, root.getLong("generatedAtEpochMillis"))
        val session = root.getJSONArray("sessions").getJSONObject(0)
        assertEquals("CHAIN_CDN", session.getString("selectedPathKind"))
        assertEquals("TLS_TCP", session.getString("selectedTransportKind"))
        assertEquals("POSSIBLE_HARD_WHITELIST", session.getString("rawRestrictionClass"))
        assertEquals("FAILED", session.getString("outcome"))
        assertEquals("RELAY_END_TO_END_PROOF_FAILED", session.getString("failureReason"))
    }

    @Test
    fun `bundle size is bounded by the store's own retention cap - never unlimited`() {
        val sessions = (1..DiagnosticSessionStore.MAX_RETAINED_SESSIONS).map { sessionWithTag("safe").copy(sessionId = "s$it") }
        val bundle = buildSupportBundle(sessions, "1.0", 1L, nowEpochMillis = 5_000L)
        assertEquals(DiagnosticSessionStore.MAX_RETAINED_SESSIONS, bundle.sessions.size)
        // Sanity bound on serialized size - a handful of sessions with bounded event counts must stay well under 1MB.
        assertTrue(bundle.toJson().length < 1_000_000)
    }

    @Test
    fun `sessionId itself is never touched by sanitization - it is a visible, non-secret grouping id`() {
        val bundle = buildSupportBundle(listOf(sessionWithTag("safe")), "1.0", 1L, nowEpochMillis = 5_000L)
        assertTrue(bundle.toJson().contains("11111111-1111-1111-1111-111111111111"))
    }
}
