package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class Shadowsocks2022CredentialTest {
    private val endpointId = EndpointId("edge-ss")
    private val validBase64 = Base64.getEncoder().encodeToString(ByteArray(32) { it.toByte() })
    private val method = "2022-blake3-aes-256-gcm"

    @Test
    fun `a valid 32-byte base64 key validates successfully`() {
        val result = Shadowsocks2022CredentialValidator.validate(endpointId, method, validBase64)
        assertTrue(result is Shadowsocks2022CredentialValidationResult.Valid)
        val credential = (result as Shadowsocks2022CredentialValidationResult.Valid).credential
        assertEquals(endpointId, credential.endpointId)
        assertEquals(method, credential.method)
        assertEquals(validBase64, credential.key.base64)
    }

    @Test
    fun `a blank secret is rejected`() {
        assertEquals(
            Shadowsocks2022CredentialValidationResult.BlankSecret,
            Shadowsocks2022CredentialValidator.validate(endpointId, method, ""),
        )
    }

    @Test
    fun `malformed base64 is rejected without parsing an exception message`() {
        assertEquals(
            Shadowsocks2022CredentialValidationResult.MalformedBase64,
            Shadowsocks2022CredentialValidator.validate(endpointId, method, "not-valid-base64!!!"),
        )
    }

    @Test
    fun `a decoded length other than 32 bytes is rejected`() {
        val shortKey = Base64.getEncoder().encodeToString(ByteArray(16))
        val result = Shadowsocks2022CredentialValidator.validate(endpointId, method, shortKey)
        assertEquals(Shadowsocks2022CredentialValidationResult.WrongDecodedLength(16), result)
    }

    @Test
    fun `an unsupported method is rejected`() {
        assertEquals(
            Shadowsocks2022CredentialValidationResult.UnsupportedMethod,
            Shadowsocks2022CredentialValidator.validate(endpointId, "some-future-cipher", validBase64),
        )
    }

    @Test
    fun `a missing (blank) endpoint id cannot even be constructed`() {
        assertThrows(IllegalArgumentException::class.java) { EndpointId("") }
    }

    @Test
    fun `the real secret never appears in Shadowsocks2022Credential toString`() {
        val credential = (
            Shadowsocks2022CredentialValidator.validate(endpointId, method, validBase64)
                as Shadowsocks2022CredentialValidationResult.Valid
            ).credential
        assertFalse(credential.toString().contains(validBase64))
        assertTrue(credential.toString().contains("<redacted>"))
    }

    @Test
    fun `the real secret never appears in Shadowsocks2022SecretKey toString`() {
        val credential = (
            Shadowsocks2022CredentialValidator.validate(endpointId, method, validBase64)
                as Shadowsocks2022CredentialValidationResult.Valid
            ).credential
        assertFalse(credential.key.toString().contains(validBase64))
        assertEquals("Shadowsocks2022SecretKey(<redacted>)", credential.key.toString())
    }

    @Test
    fun `two credentials with the same key material are equal - equals is not identity-only`() {
        val a = (Shadowsocks2022CredentialValidator.validate(endpointId, method, validBase64) as Shadowsocks2022CredentialValidationResult.Valid).credential
        val b = (Shadowsocks2022CredentialValidator.validate(endpointId, method, validBase64) as Shadowsocks2022CredentialValidationResult.Valid).credential
        assertEquals(a, b)
    }
}
