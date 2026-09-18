package net.pocvpn.client.identity

import java.util.Base64
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.Shadowsocks2022Profile
import net.pocvpn.client.reachability.SignedTransportProfile
import net.pocvpn.client.reachability.SignedTransportProfileReadResult
import net.pocvpn.client.reachability.signedTransportProfile
import net.pocvpn.client.reachability.withShadowsocks2022Profile
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45B-2 Phase 7 - proves the public/secret split between B45B-1's
 * [SignedTransportProfile.Shadowsocks2022] (signed, public metadata) and
 * B45B-2's [Shadowsocks2022Credential] (device-local secret) actually holds:
 * a real credential's key material never appears anywhere in the signed
 * profile's serialized form, even though both share the same [EndpointId]
 * and `method` string. Deliberately in the `identity` package (not
 * `reachability`) since it imports both B45B-1 and B45B-2 types.
 */
class Shadowsocks2022ProfileSeparationTest {
    private val endpointId = EndpointId("edge-ss")
    private val method = "2022-blake3-aes-256-gcm"
    private val realSecretBase64 = Base64.getEncoder().encodeToString(ByteArray(32) { (it * 7).toByte() })

    @Test
    fun `a real credential's key material never appears in the signed profile's encoded metadata`() {
        val credential = (
            Shadowsocks2022CredentialValidator.validate(endpointId, method, realSecretBase64)
                as Shadowsocks2022CredentialValidationResult.Valid
            ).credential

        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .withShadowsocks2022Profile(Shadowsocks2022Profile(method))

        // The only place the profile's encoded bytes are observable from outside is via its metadata map.
        val encodedProfile = binding.metadata.getValue("shadowsocks2022Profile")
        assertFalse(encodedProfile.contains(realSecretBase64))
        assertFalse(encodedProfile.contains(credential.key.base64))
    }

    @Test
    fun `signedTransportProfile's typed Shadowsocks2022 case carries only method - no key field exists to leak`() {
        val binding = EndpointTransportBinding(TransportKind.SHADOWSOCKS_2022, "ss.example", 28388)
            .withShadowsocks2022Profile(Shadowsocks2022Profile(method))
        val result = binding.signedTransportProfile(endpointId) as SignedTransportProfileReadResult.Parsed
        val profile = (result.profile as SignedTransportProfile.Shadowsocks2022).profile

        // Shadowsocks2022Profile's only declared property is `method` - documented by name so a future
        // field addition (e.g. an accidental key) is caught by a reviewer reading a failing assertion.
        assertEquals(
            setOf("method"),
            Shadowsocks2022Profile::class.java.declaredFields.map { it.name }.filter { !it.startsWith("$") }.toSet(),
        )
        assertTrue(profile.method == method)
    }
}
