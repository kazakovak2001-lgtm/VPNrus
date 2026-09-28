package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class Hysteria2CredentialTest {
    private val endpointId = EndpointId("edge-hy2")
    private val validAuthSecret = "a".repeat(64)

    @Test
    fun `a valid auth secret with no obfuscation secret validates successfully`() {
        val result = Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, null)
        assertTrue(result is Hysteria2CredentialValidationResult.Valid)
        val credential = (result as Hysteria2CredentialValidationResult.Valid).credential
        assertEquals(endpointId, credential.endpointId)
        assertEquals(validAuthSecret, credential.authSecret.value)
        assertNull(credential.obfuscationSecret)
    }

    @Test
    fun `a valid auth secret with a valid obfuscation secret validates successfully`() {
        val obfuscationSecret = "b".repeat(64)
        val result = Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, obfuscationSecret)
        assertTrue(result is Hysteria2CredentialValidationResult.Valid)
        val credential = (result as Hysteria2CredentialValidationResult.Valid).credential
        assertEquals(obfuscationSecret, credential.obfuscationSecret?.value)
    }

    @Test
    fun `a blank auth secret is rejected`() {
        assertEquals(
            Hysteria2CredentialValidationResult.BlankAuthSecret,
            Hysteria2CredentialValidator.validate(endpointId, "", null),
        )
    }

    @Test
    fun `an oversized auth secret is rejected`() {
        assertEquals(
            Hysteria2CredentialValidationResult.AuthSecretTooLong,
            Hysteria2CredentialValidator.validate(endpointId, "a".repeat(Hysteria2CredentialValidator.MAX_SECRET_LENGTH + 1), null),
        )
    }

    @Test
    fun `a blank obfuscation secret is rejected distinctly from absent`() {
        assertEquals(
            Hysteria2CredentialValidationResult.BlankObfuscationSecret,
            Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, ""),
        )
    }

    @Test
    fun `an oversized obfuscation secret is rejected`() {
        assertEquals(
            Hysteria2CredentialValidationResult.ObfuscationSecretTooLong,
            Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, "b".repeat(Hysteria2CredentialValidator.MAX_SECRET_LENGTH + 1)),
        )
    }

    @Test
    fun `the real auth secret never appears in Hysteria2Credential toString`() {
        val credential = (Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, "b".repeat(64)) as Hysteria2CredentialValidationResult.Valid).credential
        val text = credential.toString()
        assertFalse(text.contains(validAuthSecret))
        assertFalse(text.contains("b".repeat(64)))
        assertTrue(text.contains("<redacted>"))
    }

    @Test
    fun `the real secret never appears in Hysteria2AuthSecret toString`() {
        val credential = (Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, null) as Hysteria2CredentialValidationResult.Valid).credential
        assertEquals("Hysteria2AuthSecret(<redacted>)", credential.authSecret.toString())
    }

    @Test
    fun `the real secret never appears in Hysteria2ObfuscationSecret toString`() {
        val credential = (Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, "b".repeat(64)) as Hysteria2CredentialValidationResult.Valid).credential
        assertEquals("Hysteria2ObfuscationSecret(<redacted>)", credential.obfuscationSecret.toString())
    }

    @Test
    fun `two credentials with the same secret material are equal - equals is not identity-only`() {
        val a = (Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, null) as Hysteria2CredentialValidationResult.Valid).credential
        val b = (Hysteria2CredentialValidator.validate(endpointId, validAuthSecret, null) as Hysteria2CredentialValidationResult.Valid).credential
        assertEquals(a, b)
    }
}
