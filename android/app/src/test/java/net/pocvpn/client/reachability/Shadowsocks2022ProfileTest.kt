package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** B45B-1 - types + metadata only. Mirrors [SignedTransportProfileTest]'s own CdnXhttp coverage pattern. */
class Shadowsocks2022ProfileTest {
    private val endpointId = EndpointId("edge-ss")

    @Test
    fun `a binding with no shadowsocks profile metadata reads as Missing`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
        assertEquals(Shadowsocks2022ProfileReadResult.Missing, binding.shadowsocks2022Profile())
    }

    @Test
    fun `signedTransportProfile falls back to Legacy when no shadowsocks profile is set - not silently mapped to another runtime`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
        val result = binding.signedTransportProfile(endpointId)
        assertTrue(result is SignedTransportProfileReadResult.Parsed)
        assertEquals(
            SignedTransportProfile.Legacy(endpointId, TransportKind.SHADOWSOCKS_2022),
            (result as SignedTransportProfileReadResult.Parsed).profile,
        )
    }

    @Test
    fun `a real shadowsocks2022 profile round-trips through the metadata encoding`() {
        val profile = Shadowsocks2022Profile(method = "2022-blake3-aes-256-gcm")
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .withShadowsocks2022Profile(profile)

        val read = binding.shadowsocks2022Profile()
        assertTrue(read is Shadowsocks2022ProfileReadResult.Parsed)
        assertEquals(profile, (read as Shadowsocks2022ProfileReadResult.Parsed).profile)
    }

    @Test
    fun `signedTransportProfile returns a typed Shadowsocks2022 profile bound to the exact endpoint identity supplied by caller`() {
        val profile = Shadowsocks2022Profile(method = "2022-blake3-aes-256-gcm")
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .withShadowsocks2022Profile(profile)

        val result = binding.signedTransportProfile(endpointId) as SignedTransportProfileReadResult.Parsed
        assertEquals(TransportKind.SHADOWSOCKS_2022, result.profile.transportKind)
        assertEquals(endpointId, result.profile.endpointId)
        assertEquals(profile, (result.profile as SignedTransportProfile.Shadowsocks2022).profile)
    }

    @Test
    fun `unrecognized method fails closed as Invalid, never trusted as-is`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .copy(metadata = mapOf("shadowsocks2022Profile" to "{\"version\":1,\"method\":\"some-future-cipher\"}"))
        assertEquals(Shadowsocks2022ProfileReadResult.Invalid, binding.shadowsocks2022Profile())
    }

    @Test
    fun `unsupported profile version fails closed as Unsupported, not Invalid`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .copy(metadata = mapOf("shadowsocks2022Profile" to "{\"version\":999,\"method\":\"2022-blake3-aes-256-gcm\"}"))
        assertEquals(Shadowsocks2022ProfileReadResult.UnsupportedVersion, binding.shadowsocks2022Profile())
        assertEquals(SignedTransportProfileReadResult.Unsupported, binding.signedTransportProfile(endpointId))
    }

    @Test
    fun `the profile carries no secret field - only a pinned public method identifier`() {
        val profile = Shadowsocks2022Profile(method = "2022-blake3-aes-256-gcm")
        // Shadowsocks2022Profile's only declared property is `method` - this test documents that
        // invariant by name so a future field addition (e.g. an accidental key) is caught by a
        // reviewer reading a failing assertion, not silently.
        assertEquals(setOf("method"), Shadowsocks2022Profile::class.java.declaredFields.map { it.name }.filter { !it.startsWith("$") }.toSet())
        assertEquals("2022-blake3-aes-256-gcm", profile.method)
    }

    @Test
    fun `existing CdnXhttp profile behavior is unchanged by adding the Shadowsocks2022 case`() {
        val binding = EndpointTransportBinding(TransportKind.XRAY_XHTTP, "edge.example", 443)
        val result = binding.signedTransportProfile(endpointId)
        assertTrue(result is SignedTransportProfileReadResult.Parsed)
        assertEquals(
            SignedTransportProfile.Legacy(endpointId, TransportKind.XRAY_XHTTP),
            (result as SignedTransportProfileReadResult.Parsed).profile,
        )
    }

    @Test
    fun `a wrong-kind binding never parses a shadowsocks profile even if the metadata key is present`() {
        val binding = EndpointTransportBinding(TransportKind.TLS_TCP, "tls.example", 443)
            .copy(metadata = mapOf("shadowsocks2022Profile" to "{\"version\":1,\"method\":\"2022-blake3-aes-256-gcm\"}"))
        assertEquals(Shadowsocks2022ProfileReadResult.Invalid, binding.shadowsocks2022Profile())
        assertFalse(binding.signedTransportProfile(endpointId).let { it is SignedTransportProfileReadResult.Parsed && it.profile is SignedTransportProfile.Shadowsocks2022 })
    }
}
