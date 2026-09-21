package net.pocvpn.client.identity

import net.pocvpn.client.reachability.EndpointId

/**
 * B46-4A - the device-local SECRET half of a Hysteria2 endpoint's config
 * (see docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "signed/public
 * profile" + "secret Hysteria credential" sections; the public half is
 * [net.pocvpn.client.reachability.SignedTransportProfile.Hysteria2]). An
 * opaque wrapper, not a raw `String`, so the real wire-auth secret cannot
 * accidentally leak through a default `toString()`/log call the way a bare
 * `String` field would - mirrors [Shadowsocks2022SecretKey]'s own redaction
 * discipline exactly. This is the Hysteria2-specific, per-device DATA-PLANE
 * credential - never the user's activation bearer credential (see
 * [Hysteria2ProfileProvisioner]'s own "no raw activation credential as
 * Hysteria auth" doc).
 */
class Hysteria2AuthSecret internal constructor(internal val value: String) {
    override fun toString(): String = "Hysteria2AuthSecret(<redacted>)"
    override fun equals(other: Any?): Boolean = other is Hysteria2AuthSecret && value == other.value
    override fun hashCode(): Int = value.hashCode()
}

/**
 * B46-4A - optional Salamander obfuscation password, present only when the
 * endpoint's signed [net.pocvpn.client.reachability.Hysteria2Profile.obfuscationMode]
 * is `"SALAMANDER"`. Same redaction discipline as [Hysteria2AuthSecret].
 */
class Hysteria2ObfuscationSecret internal constructor(internal val value: String) {
    override fun toString(): String = "Hysteria2ObfuscationSecret(<redacted>)"
    override fun equals(other: Any?): Boolean = other is Hysteria2ObfuscationSecret && value == other.value
    override fun hashCode(): Int = value.hashCode()
}

/**
 * B46-4A - one endpoint-bound Hysteria2 credential: [endpointId] + the wire
 * auth secret + an optional Salamander obfuscation secret.
 * [Hysteria2CredentialValidator] is the only place that constructs a
 * validated instance from untrusted input (a provisioning response or a
 * decrypted repository payload). Never part of
 * [net.pocvpn.client.reachability.SignedTransportProfile] or
 * `EndpointManifest` - this type only ever lives in device-local encrypted
 * storage (see `Hysteria2CredentialRepository`).
 */
data class Hysteria2Credential(
    val endpointId: EndpointId,
    val authSecret: Hysteria2AuthSecret,
    val obfuscationSecret: Hysteria2ObfuscationSecret?,
) {
    /** Never expose the real secrets in a log or crash report (mirrors [Shadowsocks2022Credential]'s own redaction discipline). */
    override fun toString(): String =
        "Hysteria2Credential(endpointId=$endpointId, authSecret=<redacted>, obfuscationSecret=${if (obfuscationSecret != null) "<redacted>" else "null"})"
}

sealed interface Hysteria2CredentialValidationResult {
    data class Valid(val credential: Hysteria2Credential) : Hysteria2CredentialValidationResult
    data object BlankAuthSecret : Hysteria2CredentialValidationResult
    data object AuthSecretTooLong : Hysteria2CredentialValidationResult
    data object BlankObfuscationSecret : Hysteria2CredentialValidationResult
    data object ObfuscationSecretTooLong : Hysteria2CredentialValidationResult
}

/**
 * Deterministic, local, typed validation - never exception-message parsing,
 * never logs the rejected input (mirrors [Shadowsocks2022CredentialValidator]'s
 * own doc). [obfuscationSecretRaw] being non-null but blank is rejected
 * distinctly from it being absent - a caller that means "no Salamander
 * secret" must pass `null`, never an empty string.
 */
object Hysteria2CredentialValidator {
    // Hysteria2's own wire auth string has no fixed upstream length limit;
    // this is a conservative, generous local sanity bound only (never a
    // format assumption), matching the same "bounded, not exact-length"
    // discipline this codebase already applies to free-form secret fields.
    const val MAX_SECRET_LENGTH = 256

    fun validate(endpointId: EndpointId, authSecretRaw: String, obfuscationSecretRaw: String?): Hysteria2CredentialValidationResult {
        if (authSecretRaw.isBlank()) return Hysteria2CredentialValidationResult.BlankAuthSecret
        if (authSecretRaw.length > MAX_SECRET_LENGTH) return Hysteria2CredentialValidationResult.AuthSecretTooLong
        val obfuscationSecret = if (obfuscationSecretRaw != null) {
            if (obfuscationSecretRaw.isBlank()) return Hysteria2CredentialValidationResult.BlankObfuscationSecret
            if (obfuscationSecretRaw.length > MAX_SECRET_LENGTH) return Hysteria2CredentialValidationResult.ObfuscationSecretTooLong
            Hysteria2ObfuscationSecret(obfuscationSecretRaw)
        } else {
            null
        }
        return Hysteria2CredentialValidationResult.Valid(
            Hysteria2Credential(endpointId, Hysteria2AuthSecret(authSecretRaw), obfuscationSecret),
        )
    }
}
