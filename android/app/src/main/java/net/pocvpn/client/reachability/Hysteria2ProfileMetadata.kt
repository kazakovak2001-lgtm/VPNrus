package net.pocvpn.client.reachability

import net.pocvpn.client.transport.TransportKind
import org.json.JSONException
import org.json.JSONObject
import org.json.JSONTokener

private const val HYSTERIA2_PROFILE_KEY = "hysteria2Profile"
private const val HYSTERIA2_PROFILE_VERSION = 1L
private const val MAX_PROFILE_BYTES = 512 // Small on purpose - PUBLIC facts only, no key material.
private const val MAX_SNI_LENGTH = 253 // RFC 1035 max DNS name length.

/**
 * B46-4A - the closed, non-secret Hysteria2 obfuscation-mode identifiers
 * this typed profile is willing to represent - mirrors
 * [SUPPORTED_SHADOWSOCKS_METHODS]'s own "closed set, not a freeform string"
 * discipline. `NONE` is no obfuscation layer; `SALAMANDER` names the
 * upstream `obfs: {type: salamander, salamander: {password: ...}}`
 * mechanism (the SALAMANDER PASSWORD itself is secret material and never
 * appears here - see [net.pocvpn.client.identity.Hysteria2Credential]'s own
 * doc for where it actually lives).
 */
internal val SUPPORTED_HYSTERIA2_OBFUSCATION_MODES = setOf("NONE", "SALAMANDER")

/**
 * B46-4A - the PUBLIC/SIGNED half of a Hysteria2 endpoint's config (mirrors
 * [Shadowsocks2022Profile]'s own public/secret split - see
 * docs/B46_4A_HYSTERIA2_PRODUCTION_INTEGRATION.md's "signed/public profile"
 * section). [sni]/[obfuscationMode] are the only fields beyond what
 * [EndpointTransportBinding] already carries (host/port/kind); the Hysteria
 * auth secret and any Salamander obfuscation password are device-local
 * secret material and deliberately have no place here.
 */
data class Hysteria2Profile(val sni: String, val obfuscationMode: String)

sealed interface Hysteria2ProfileReadResult {
    data object Missing : Hysteria2ProfileReadResult
    data object Invalid : Hysteria2ProfileReadResult
    data object UnsupportedVersion : Hysteria2ProfileReadResult
    data class Parsed(val profile: Hysteria2Profile) : Hysteria2ProfileReadResult
}

private fun isValidSni(sni: String): Boolean {
    if (sni.isBlank() || sni.length > MAX_SNI_LENGTH) return false
    // Conservative charset: DNS-name-shaped only (letters, digits, '-', '.'),
    // never an IP literal or anything URL/credential-shaped (defense in
    // depth alongside the record-validator-style secret-shaped scan this
    // codebase's other typed profiles already rely on their own narrow
    // closed schemas for).
    return sni.all { it.isLetterOrDigit() || it == '-' || it == '.' } && !sni.startsWith(".") && !sni.endsWith(".")
}

/** Parse only; this is neither a signature verifier nor a runtime capability/reachability gate (mirrors [shadowsocks2022Profile]'s own doc). */
fun EndpointTransportBinding.hysteria2Profile(): Hysteria2ProfileReadResult {
    val raw = metadata[HYSTERIA2_PROFILE_KEY] ?: return Hysteria2ProfileReadResult.Missing
    if (kind != TransportKind.HYSTERIA2 || raw.toByteArray(Charsets.UTF_8).size > MAX_PROFILE_BYTES) {
        return Hysteria2ProfileReadResult.Invalid
    }
    return try {
        val tokens = JSONTokener(raw)
        val json = tokens.nextValue() as? JSONObject ?: return Hysteria2ProfileReadResult.Invalid
        require(tokens.nextClean() == ' ')
        require(json.keys().asSequence().toSet() == setOf("version", "sni", "obfuscationMode"))
        val version = json.get("version") as? Long ?: (json.get("version") as? Int)?.toLong()
            ?: return Hysteria2ProfileReadResult.Invalid
        if (version != HYSTERIA2_PROFILE_VERSION) return Hysteria2ProfileReadResult.UnsupportedVersion
        val sni = json.get("sni") as? String ?: return Hysteria2ProfileReadResult.Invalid
        if (!isValidSni(sni)) return Hysteria2ProfileReadResult.Invalid
        val obfuscationMode = json.get("obfuscationMode") as? String ?: return Hysteria2ProfileReadResult.Invalid
        if (obfuscationMode !in SUPPORTED_HYSTERIA2_OBFUSCATION_MODES) return Hysteria2ProfileReadResult.Invalid
        Hysteria2ProfileReadResult.Parsed(Hysteria2Profile(sni, obfuscationMode))
    } catch (_: IllegalArgumentException) {
        Hysteria2ProfileReadResult.Invalid
    } catch (_: JSONException) {
        Hysteria2ProfileReadResult.Invalid
    }
}

/** Preserves unrelated metadata and the existing signed manifest schema. New content still needs signing (mirrors [withShadowsocks2022Profile]'s own doc). */
fun EndpointTransportBinding.withHysteria2Profile(profile: Hysteria2Profile): EndpointTransportBinding {
    require(kind == TransportKind.HYSTERIA2)
    require(isValidSni(profile.sni)) { "invalid SNI" }
    require(profile.obfuscationMode in SUPPORTED_HYSTERIA2_OBFUSCATION_MODES) { "unsupported obfuscation mode" }
    val encoded = JSONObject().apply {
        put("version", HYSTERIA2_PROFILE_VERSION)
        put("sni", profile.sni)
        put("obfuscationMode", profile.obfuscationMode)
    }.toString()
    require(encoded.toByteArray(Charsets.UTF_8).size <= MAX_PROFILE_BYTES)
    require((metadata.keys + HYSTERIA2_PROFILE_KEY).size <= 64)
    val binding = copy(metadata = metadata + (HYSTERIA2_PROFILE_KEY to encoded))
    require(binding.hysteria2Profile() is Hysteria2ProfileReadResult.Parsed)
    return binding
}
