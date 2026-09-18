package net.pocvpn.client.identity

import java.util.Base64
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.SUPPORTED_SHADOWSOCKS_METHODS

/**
 * B45B-2 - the device-local SECRET half of a Shadowsocks 2022 endpoint's
 * config (see docs/B45B_SHADOWSOCKS_PRODUCTION_ADAPTER_DESIGN.md Section
 * 10/13's own public/secret split; the public half is
 * `net.pocvpn.client.reachability.SignedTransportProfile.Shadowsocks2022`,
 * B45B-1). An opaque wrapper, not a raw `String`, so the real key material
 * cannot accidentally leak through a default `toString()`/log call the way a
 * bare `String` field would - [toString] is permanently redacted.
 */
class Shadowsocks2022SecretKey internal constructor(internal val base64: String) {
    override fun toString(): String = "Shadowsocks2022SecretKey(<redacted>)"
    override fun equals(other: Any?): Boolean = other is Shadowsocks2022SecretKey && base64 == other.base64
    override fun hashCode(): Int = base64.hashCode()
}

/**
 * B45B-2 - one endpoint-bound Shadowsocks 2022 credential:
 * [endpointId] + the pinned [method] + the AEAD-2022 raw key
 * (base64-encoded, exactly 32 decoded bytes - [Shadowsocks2022CredentialValidator]
 * is the only place that constructs a validated instance from untrusted
 * input). Never part of [net.pocvpn.client.reachability.SignedTransportProfile] or
 * `EndpointManifest` (see [Shadowsocks2022ProfileSeparationTest] in the test
 * source set) - this type only ever lives in device-local encrypted storage
 * (see [Shadowsocks2022CredentialRepository]).
 */
data class Shadowsocks2022Credential(
    val endpointId: EndpointId,
    val method: String,
    val key: Shadowsocks2022SecretKey,
) {
    /** Never expose the real key in a log or crash report (mirrors [XrayProfile]'s own redaction discipline). */
    override fun toString(): String = "Shadowsocks2022Credential(endpointId=$endpointId, method=$method, key=<redacted>)"
}

sealed interface Shadowsocks2022CredentialValidationResult {
    data class Valid(val credential: Shadowsocks2022Credential) : Shadowsocks2022CredentialValidationResult
    data object BlankSecret : Shadowsocks2022CredentialValidationResult
    data object MalformedBase64 : Shadowsocks2022CredentialValidationResult
    data class WrongDecodedLength(val actualBytes: Int) : Shadowsocks2022CredentialValidationResult
    data object UnsupportedMethod : Shadowsocks2022CredentialValidationResult
}

/**
 * Deterministic, local, typed validation - never exception-message parsing,
 * never logs the rejected input (the caller decides whether/how to surface a
 * validation failure to the user; this object never touches `Log`).
 */
object Shadowsocks2022CredentialValidator {
    const val REQUIRED_DECODED_LENGTH_BYTES = 32

    fun validate(endpointId: EndpointId, method: String, secretKeyBase64: String): Shadowsocks2022CredentialValidationResult {
        if (method !in SUPPORTED_SHADOWSOCKS_METHODS) return Shadowsocks2022CredentialValidationResult.UnsupportedMethod
        if (secretKeyBase64.isBlank()) return Shadowsocks2022CredentialValidationResult.BlankSecret
        val decoded = try {
            Base64.getDecoder().decode(secretKeyBase64)
        } catch (_: IllegalArgumentException) {
            return Shadowsocks2022CredentialValidationResult.MalformedBase64
        }
        if (decoded.size != REQUIRED_DECODED_LENGTH_BYTES) {
            return Shadowsocks2022CredentialValidationResult.WrongDecodedLength(decoded.size)
        }
        return Shadowsocks2022CredentialValidationResult.Valid(
            Shadowsocks2022Credential(endpointId, method, Shadowsocks2022SecretKey(secretKeyBase64)),
        )
    }
}
