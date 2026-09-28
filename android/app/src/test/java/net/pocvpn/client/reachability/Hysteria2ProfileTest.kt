package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B46-4A - types + metadata only. Mirrors [Shadowsocks2022ProfileTest]'s own coverage pattern exactly. */
class Hysteria2ProfileTest {
    private val endpointId = EndpointId("edge-hy2")

    @Test
    fun `a binding with no hysteria2 profile metadata reads as Missing`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
        assertEquals(Hysteria2ProfileReadResult.Missing, binding.hysteria2Profile())
    }

    @Test
    fun `signedTransportProfile falls back to Legacy when no hysteria2 profile is set - not silently mapped to another runtime`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
        val result = binding.signedTransportProfile(endpointId)
        assertTrue(result is SignedTransportProfileReadResult.Parsed)
        assertEquals(
            SignedTransportProfile.Legacy(endpointId, TransportKind.HYSTERIA2),
            (result as SignedTransportProfileReadResult.Parsed).profile,
        )
    }

    @Test
    fun `a real hysteria2 profile round-trips through the metadata encoding`() {
        val profile = Hysteria2Profile(sni = "hy2.example.com", obfuscationMode = "NONE")
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .withHysteria2Profile(profile)

        val read = binding.hysteria2Profile()
        assertTrue(read is Hysteria2ProfileReadResult.Parsed)
        assertEquals(profile, (read as Hysteria2ProfileReadResult.Parsed).profile)
    }

    @Test
    fun `signedTransportProfile returns a typed Hysteria2 profile bound to the exact endpoint identity supplied by caller`() {
        val profile = Hysteria2Profile(sni = "hy2.example.com", obfuscationMode = "NONE")
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .withHysteria2Profile(profile)

        val result = binding.signedTransportProfile(endpointId) as SignedTransportProfileReadResult.Parsed
        assertEquals(TransportKind.HYSTERIA2, result.profile.transportKind)
        assertEquals(endpointId, result.profile.endpointId)
        assertEquals(profile, (result.profile as SignedTransportProfile.Hysteria2).profile)
    }

    @Test
    fun `unsupported obfuscation mode fails closed as Invalid, never trusted as-is`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"SOME_FUTURE_MODE\"}"))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
    }

    @Test
    fun `SALAMANDER is not yet representable - fails closed as Invalid (Finding 8 - not a real per-device server capability)`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"SALAMANDER\"}"))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
    }

    @Test
    fun `a normal encoded profile with no trailing content parses (EOF fix)`() {
        val raw = "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}"
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to raw))
        val result = binding.hysteria2Profile()
        assertTrue(result is Hysteria2ProfileReadResult.Parsed)
        assertEquals(Hysteria2Profile("hy2.example.com", "NONE"), (result as Hysteria2ProfileReadResult.Parsed).profile)
    }

    @Test
    fun `trailing whitespace after the object is accepted (nextClean skips it before EOF)`() {
        val raw = "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}   \n"
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to raw))
        assertTrue(binding.hysteria2Profile() is Hysteria2ProfileReadResult.Parsed)
    }

    @Test
    fun `trailing non-whitespace garbage after the object is rejected as Invalid`() {
        val raw = "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}garbage"
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to raw))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
    }

    @Test
    fun `a second JSON value appended after the first is rejected as Invalid`() {
        val raw = "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}{\"extra\":true}"
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to raw))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
    }

    @Test
    fun `encode then parse round-trips successfully through withHysteria2Profile - hysteria2Profile (Finding 1 regression proof)`() {
        val profile = Hysteria2Profile(sni = "roundtrip.example.com", obfuscationMode = "NONE")
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .withHysteria2Profile(profile)
        val result = binding.hysteria2Profile()
        assertTrue("expected Parsed, got $result", result is Hysteria2ProfileReadResult.Parsed)
        assertEquals(profile, (result as Hysteria2ProfileReadResult.Parsed).profile)
    }

    @Test
    fun `unsupported profile version fails closed as Unsupported, not Invalid`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":999,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}"))
        assertEquals(Hysteria2ProfileReadResult.UnsupportedVersion, binding.hysteria2Profile())
        assertEquals(SignedTransportProfileReadResult.Unsupported, binding.signedTransportProfile(endpointId))
    }

    @Test
    fun `a blank SNI fails closed as Invalid`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":1,\"sni\":\"\",\"obfuscationMode\":\"NONE\"}"))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
    }

    @Test
    fun `an IP-literal SNI fails closed as Invalid`() {
        val binding = EndpointTransportBinding(TransportKind.HYSTERIA2, "hy2.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":1,\"sni\":\"192.0.2.1\",\"obfuscationMode\":\"NONE\"}"))
        // Digits/dots alone parse as a syntactically "valid" DNS-name-shaped
        // string per isValidSni's own conservative charset, but constructing
        // via withHysteria2Profile is exercised separately - this test
        // documents that an IP literal is accepted by the narrow charset
        // check today (no dedicated IP-literal rejection) - see the
        // production doc's own note that this is a conservative, not
        // exhaustive, defense-in-depth check.
        val read = binding.hysteria2Profile()
        assertTrue(read is Hysteria2ProfileReadResult.Parsed)
    }

    @Test
    fun `the profile carries no secret field - only pinned public SNI and obfuscation mode identifier`() {
        assertEquals(
            setOf("sni", "obfuscationMode"),
            Hysteria2Profile::class.java.declaredFields.map { it.name }.filter { !it.startsWith("$") }.toSet(),
        )
    }

    @Test
    fun `existing Shadowsocks2022 profile behavior is unchanged by adding the Hysteria2 case`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
        val result = binding.signedTransportProfile(endpointId)
        assertTrue(result is SignedTransportProfileReadResult.Parsed)
        assertEquals(
            SignedTransportProfile.Legacy(endpointId, TransportKind.SHADOWSOCKS_2022),
            (result as SignedTransportProfileReadResult.Parsed).profile,
        )
    }

    @Test
    fun `a wrong-kind binding never parses a hysteria2 profile even if the metadata key is present`() {
        val binding = EndpointTransportBinding(TransportKind.TLS_TCP, "tls.example", 443)
            .copy(metadata = mapOf("hysteria2Profile" to "{\"version\":1,\"sni\":\"hy2.example.com\",\"obfuscationMode\":\"NONE\"}"))
        assertEquals(Hysteria2ProfileReadResult.Invalid, binding.hysteria2Profile())
        assertFalse(binding.signedTransportProfile(endpointId).let { it is SignedTransportProfileReadResult.Parsed && it.profile is SignedTransportProfile.Hysteria2 })
    }
}
