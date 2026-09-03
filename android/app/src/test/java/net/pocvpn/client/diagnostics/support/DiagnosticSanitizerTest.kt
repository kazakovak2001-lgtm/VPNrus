package net.pocvpn.client.diagnostics.support

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B29 (task E/K) - the required security test: construct inputs deliberately
 * containing secret sentinel strings and prove [DiagnosticSanitizer] rejects
 * every one of them.
 */
class DiagnosticSanitizerTest {

    @Test
    fun `ordinary safe values pass through unchanged`() {
        listOf("DIRECT", "CHAIN_CDN", "true", "false", "12", "AMNEZIA_WG", "END_TO_END_DATA_PLANE_OK", "").forEach {
            assertTrue("'$it' should be considered safe", DiagnosticSanitizer.isSafeValue(it))
            assertEquals(it, DiagnosticSanitizer.sanitize(it))
        }
    }

    @Test
    fun `a UUID-shaped activation credential or tunnel identity is rejected`() {
        val sentinel = "SECRET-2f6b9e2a-3c1d-4e5f-8a9b-1234567890ab"
        assertFalse(DiagnosticSanitizer.isSafeValue(sentinel))
        assertEquals("[redacted]", DiagnosticSanitizer.sanitize(sentinel))
    }

    @Test
    fun `a long base64 AWG or REALITY private key is rejected`() {
        val sentinel = "SECRET-hU7ohcV8fjAtDFISvpnfLhYFSlxY4lso0XofszDN81Y="
        assertFalse(DiagnosticSanitizer.isSafeValue(sentinel))
    }

    @Test
    fun `a bearer auth header is rejected`() {
        val sentinel = "Authorization: Bearer sk_live_SECRETTOKEN1234567890"
        assertFalse(DiagnosticSanitizer.isSafeValue(sentinel))
    }

    @Test
    fun `a PEM-shaped private key block is rejected`() {
        val sentinel = "-----BEGIN PRIVATE KEY-----\nMIIBSECRETMATERIAL\n-----END PRIVATE KEY-----"
        assertFalse(DiagnosticSanitizer.isSafeValue(sentinel))
    }

    @Test
    fun `a probe token or credential key-value pair is rejected`() {
        listOf("probe_token=SECRETVALUE123", "activation_credential: SECRETVALUE123", "password=hunter2SECRET").forEach {
            assertFalse("'$it' should be rejected", DiagnosticSanitizer.isSafeValue(it))
        }
    }

    @Test
    fun `a URL carrying secret query data is rejected`() {
        val sentinel = "https://gateway.example.net/v1/activate?token=SECRETVALUE"
        assertFalse(DiagnosticSanitizer.isSafeValue(sentinel))
    }

    @Test
    fun `an endpoint host or bare URL is rejected`() {
        listOf("https://152.70.43.1:8443/", "http://ingress.internal.example/").forEach {
            assertFalse("'$it' should be rejected", DiagnosticSanitizer.isSafeValue(it))
        }
    }

    @Test
    fun `an IPv4 or IPv6 address is rejected`() {
        listOf("152.70.43.1", "2001:db8::1", "fe80::1234:5678:9abc:def0").forEach {
            assertFalse("'$it' should be rejected", DiagnosticSanitizer.isSafeValue(it))
        }
    }

    @Test
    fun `sanitizeTags redacts only the unsafe values, keys are left untouched`() {
        val tags = mapOf(
            "pathKind" to "CHAIN_CDN",
            "leakedSecret" to "Bearer sk_live_SECRETTOKEN1234567890",
        )
        val sanitized = DiagnosticSanitizer.sanitizeTags(tags)
        assertEquals("CHAIN_CDN", sanitized["pathKind"])
        assertEquals("[redacted]", sanitized["leakedSecret"])
        assertEquals(tags.keys, sanitized.keys)
    }
}
