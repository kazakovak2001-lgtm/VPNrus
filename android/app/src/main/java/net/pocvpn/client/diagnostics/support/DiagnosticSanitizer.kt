package net.pocvpn.client.diagnostics.support

/**
 * B29 (task E) - the ONE explicit sanitizer/export boundary. Pure, no I/O,
 * no Android dependency - directly unit-testable with concrete secret
 * sentinel strings (task's own required security test).
 *
 * This is DEFENSE IN DEPTH, not the primary defense: the primary defense is
 * structural - [SupportDiagnosticsRecorder]'s typed `record*` functions
 * never accept a raw free-text string in the first place (every
 * [net.pocvpn.client.diagnostics.support.DiagnosticEvent.tags] value the
 * production recorder ever writes is an enum name, a bounded integer/boolean
 * rendered as text, a pinned non-secret EndpointId, or
 * [net.pocvpn.client.reachability.NetworkFingerprinter]'s own opaque output
 * - never a host or credential from a network response or profile.
 * [isSafeValue] is the SECOND, independent check [buildSupportBundle] runs
 * over every event tag value before serialization, so a future
 * call site that accidentally passes something secret-shaped is still
 * caught rather than silently exported.
 */
object DiagnosticSanitizer {

    // Operator endpoint IDs are short slugs. Reject host/URL/path-shaped or
    // otherwise unexpected IDs even if the generic secret-shape scan misses
    // them. This affects support export only, never candidate eligibility.
    private val ENDPOINT_ID_REGEX = Regex("[a-z][a-z0-9_-]{0,127}")
    private val ENDPOINT_ID_TAGS = setOf("plannedEndpointId", "attemptedEndpointId", "plannedIngressEndpointId", "attemptedIngressEndpointId", "plannedExitEndpointId", "attemptedExitEndpointId")

    // A UUID (activation credentials/tunnel identities/device public-key-derived
    // ids in this codebase are all UUID-shaped or Base64 - see
    // ActivationCredential/ClientTunnelIdentity's own docs).
    private val UUID_REGEX = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

    // AWG/Xray/REALITY keys, activation credentials, and probe tokens in this
    // codebase are all long Base64(url) blobs - see AwgProfile/XrayProfile/
    // IngressClientProfile's own key fields. 24+ chars catches a 16-byte key
    // (22 chars unpadded) and up. Requires at least one lowercase letter so
    // an UPPER_SNAKE_CASE enum name (this codebase's own typed-token
    // convention, e.g. "END_TO_END_DATA_PLANE_OK") is never flagged - real
    // key material is effectively always mixed-case.
    private val BASE64_CANDIDATE_REGEX = Regex("[A-Za-z0-9+/_-]{24,}={0,2}")

    private val AUTH_HEADER_REGEX = Regex("(?i)bearer\\s+\\S+")
    private val PEM_BLOCK_REGEX = Regex("-----BEGIN [A-Z0-9 ]+-----")
    // No \b before the keyword - "probe_token=" must match even though "_"
    // is itself a word character (no boundary exists between "_" and "t").
    private val CREDENTIAL_KV_REGEX = Regex("(?i)(token|secret|password|credential|apikey|api[_-]?key|private[_-]?key)[_-]?\\s*[:=]")
    private val URL_WITH_QUERY_REGEX = Regex("(?i)https?://\\S+\\?\\S+")
    private val IPV4_REGEX = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")
    private val IPV6_REGEX = Regex("(?i)\\b[0-9a-f]{0,4}(:[0-9a-f]{0,4}){3,}\\b")
    private val HOSTNAME_URL_REGEX = Regex("(?i)\\bhttps?://[^\\s\"']+")

    /**
     * True only when [value] contains none of the secret/identifying shapes
     * this file's own required blocklist names (credentials, UUIDs, private
     * keys, probe tokens, auth headers, URLs with query data, endpoint
     * hosts/IPs). A short enum name, a decimal number, or a boolean word
     * passes; anything shaped like a key, token, credential, or address does
     * not.
     */
    fun isSafeValue(value: String): Boolean {
        if (value.isBlank()) return true
        if (UUID_REGEX.containsMatchIn(value)) return false
        if (AUTH_HEADER_REGEX.containsMatchIn(value)) return false
        if (PEM_BLOCK_REGEX.containsMatchIn(value)) return false
        if (CREDENTIAL_KV_REGEX.containsMatchIn(value)) return false
        if (URL_WITH_QUERY_REGEX.containsMatchIn(value)) return false
        if (HOSTNAME_URL_REGEX.containsMatchIn(value)) return false
        if (IPV4_REGEX.containsMatchIn(value)) return false
        if (IPV6_REGEX.containsMatchIn(value)) return false
        if (BASE64_CANDIDATE_REGEX.findAll(value).any { match -> match.value.any { it.isLowerCase() } }) return false
        return true
    }

    /** Returns [value] unchanged if [isSafeValue], else a fixed, non-informative redaction marker - never a partial/truncated echo of the original (which could itself leak a prefix of a secret). */
    fun sanitize(value: String): String = if (isSafeValue(value)) value else "[redacted]"

    /** Sanitizes every value of [tags] (keys are already a closed, typed vocabulary - see [net.pocvpn.client.diagnostics.support.DiagnosticEvent]'s own docs - so only values are checked). */
    fun sanitizeTags(tags: Map<String, String>): Map<String, String> = tags.mapValues { (key, value) ->
        if (key in ENDPOINT_ID_TAGS && !ENDPOINT_ID_REGEX.matches(value)) "[redacted]" else sanitize(value)
    }
}
