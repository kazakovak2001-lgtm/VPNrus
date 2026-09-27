package net.pocvpn.client.activation

/**
 * B-ACT-IMPORT - the source-agnostic front door to activation import. Every
 * adapter (paste, file, QR, App Link) produces one of these; NONE of them
 * may perform cryptographic validation, trust decisions, or network I/O of
 * their own - that stays exclusively inside the EXISTING
 * [ActivationPackageImporter]/[ActivationPackageRedeemer]/[ActivationEnvelopeVerifier]
 * pipeline, unchanged. An adapter's only job is: "what raw text did the user
 * hand us, and where did it come from" - never "is this trustworthy".
 *
 * [Text] is the existing paste path, unchanged. [File] and [Qr] carry the
 * RAW, unmodified string an adapter extracted (from a SAF file's UTF-8
 * bytes, or a scanned QR payload) - see [ActivationInputResolver], which is
 * the ONLY place that decides what a raw string/URI means. [AppLink] carries
 * the raw https URL string from an incoming `ACTION_VIEW` Intent.
 */
sealed class ActivationInput {
    data class Text(val text: String) : ActivationInput() {
        override fun toString(): String = "Text(<${text.length} chars REDACTED>)"
    }

    data class File(val content: String) : ActivationInput() {
        override fun toString(): String = "File(<${content.length} chars REDACTED>)"
    }

    data class Qr(val payload: String) : ActivationInput() {
        override fun toString(): String = "Qr(<${payload.length} chars REDACTED>)"
    }

    data class AppLink(val url: String) : ActivationInput() {
        // The URL's host/path are NOT secret (they are, by construction, a
        // fixed production host + an opaque token) - but the token itself
        // is a bearer reference once resolved, so this stays redacted too,
        // matching every other ActivationInput variant's own discipline.
        override fun toString(): String = "AppLink(<${url.length} chars REDACTED>)"
    }
}

/** Why a source adapter's raw input could not be turned into anything the existing pipeline can consume - never a security/trust verdict. */
enum class ActivationInputRejectionReason {
    FILE_EMPTY,
    FILE_UNREADABLE,
    QR_EMPTY,
    QR_UNRECOGNIZED,
    APPLINK_WRONG_SCHEME,
    APPLINK_WRONG_HOST,
    APPLINK_WRONG_PATH,
    APPLINK_MALFORMED_TOKEN,
}

/**
 * The result of normalizing one [ActivationInput] - deliberately a CLOSED,
 * three-way outcome so a caller can never treat an unresolved input as
 * trusted:
 *
 * - [Ready] - a plain package/credential string, handed unchanged to the
 *   EXISTING [ActivationPackageInput.Text] the current paste path already
 *   uses. This is the ONLY outcome that ever reaches
 *   [ActivationPackageImporter] - signature, issuer trust, expiry, replay
 *   and gateway eligibility are ALL still evaluated there, unchanged, exactly
 *   as for a pasted credential.
 * - [NeedsHandoff] - an opaque one-time [token] from an App Link that must be
 *   exchanged with a server endpoint for the actual package. THAT ENDPOINT
 *   DOES NOT EXIST YET (see docs/ACTIVATION_HANDOFF_CONTRACT.md) - no
 *   fabricated network call is ever made here. A caller must surface this as
 *   "not yet supported", never silently proceed, and never treat the mere
 *   presence of a well-formed token as proof of anything.
 * - [Rejected] - the raw input's OWN shape was invalid (empty file, an
 *   unrecognized QR payload, a wrong App Link host/path/token shape) -
 *   purely a shape check, before the existing crypto pipeline is ever
 *   reached.
 */
sealed class ActivationInputResolution {
    data class Ready(val input: ActivationPackageInput) : ActivationInputResolution()
    data class NeedsHandoff(val token: String) : ActivationInputResolution()
    data class Rejected(val reason: ActivationInputRejectionReason) : ActivationInputResolution()
}

/**
 * B-ACT-IMPORT - pure, dependency-free, deterministic normalization from a
 * raw [ActivationInput] to an [ActivationInputResolution]. Intentionally
 * plain JVM (no `android.net.Uri`, no I/O) - same "pure/unit-testable"
 * discipline [ActivationPackageParser]/[ActivationPackageImporter] already
 * follow - so an Activity/ViewModel can call this from any thread without
 * touching Android framework classes, and every branch is covered by a
 * plain JUnit test with no Robolectric/instrumentation needed.
 *
 * This object NEVER performs signature verification, issuer trust lookup,
 * expiry/replay checks, or gateway eligibility - see [ActivationInputResolution]'s
 * own docs for why [Ready] is the only outcome the EXISTING
 * [ActivationPackageImporter] pipeline ever sees, unchanged.
 */
object ActivationInputResolver {
    /**
     * The ONE production activation App Link host this build trusts -
     * mirrors [net.pocvpn.client.vpn.config.ProductionGatewayCatalog]'s own
     * "no wildcard host, one explicit literal" discipline. Reuses this
     * project's existing `aknova.pp.ua` production domain family (see
     * [net.pocvpn.client.vpn.config.ProductionGatewayCatalog.STOCKHOLM]'s
     * `edge-sthlm.aknova.pp.ua` CDN-fronted ingress) rather than inventing an
     * unrelated placeholder domain - TODO: confirm/replace with the real
     * assigned activation subdomain before this ships; see
     * docs/ACTIVATION_HANDOFF_CONTRACT.md.
     */
    const val PRODUCTION_ACTIVATION_HOST = "activate.aknova.pp.ua"

    /** Only this one path prefix is ever accepted - never a bare `/` or a wildcard. */
    private const val ACTIVATION_PATH_PREFIX = "/a/"

    /** Same URL-safe-base64-shaped bound as an [ActivationCredential]-adjacent opaque token - generous, but never unbounded. */
    private val TOKEN_FORMAT = Regex("^[A-Za-z0-9_-]{16,256}$")

    fun resolve(input: ActivationInput): ActivationInputResolution = when (input) {
        is ActivationInput.Text -> ActivationInputResolution.Ready(ActivationPackageInput.Text(input.text))
        is ActivationInput.File -> resolveFile(input.content)
        is ActivationInput.Qr -> resolveQr(input.payload)
        is ActivationInput.AppLink -> resolveAppLinkUrl(input.url)
    }

    /**
     * [content] is the SAF file's exact UTF-8-decoded characters - the
     * caller must not trim/normalize it beyond what reading UTF-8 bytes as a
     * String already does (see [net.pocvpn.client.ui] file-picker wiring).
     * Only a fully empty/blank file is rejected here; everything else is
     * handed unchanged to [ActivationPackageInput.Text] - the SAME
     * `.trim()` (outer whitespace only, e.g. a trailing newline) that
     * [ActivationPackageParser.parse] already applies to a pasted string is
     * the only normalization that ever happens, and it happens there, not
     * here.
     */
    fun resolveFile(content: String): ActivationInputResolution {
        if (content.isBlank()) return ActivationInputResolution.Rejected(ActivationInputRejectionReason.FILE_EMPTY)
        return ActivationInputResolution.Ready(ActivationPackageInput.Text(content))
    }

    /**
     * A QR payload is supported in exactly two shapes (never a third,
     * guessed one): an `https://` App Link URL (delegates to
     * [resolveAppLinkUrl] - the SAME validation, never a second one), or an
     * offline package payload recognized by the EXISTING
     * [ActivationPackageParser.looksLikePackageText] prefix check - never a
     * new, independently-invented "looks like a package" heuristic.
     */
    fun resolveQr(payload: String): ActivationInputResolution {
        if (payload.isBlank()) return ActivationInputResolution.Rejected(ActivationInputRejectionReason.QR_EMPTY)
        val trimmed = payload.trim()
        if (trimmed.startsWith("https://", ignoreCase = true)) {
            return resolveAppLinkUrl(trimmed)
        }
        if (ActivationPackageParser.looksLikePackageText(trimmed)) {
            return ActivationInputResolution.Ready(ActivationPackageInput.Text(trimmed))
        }
        return ActivationInputResolution.Rejected(ActivationInputRejectionReason.QR_UNRECOGNIZED)
    }

    /**
     * Strict allow-list: exact scheme (`https` only, never a custom URI
     * scheme as the production mechanism - see module docs), exact host
     * (never a suffix/wildcard match), and exact path prefix. Anything else
     * is rejected before a [NeedsHandoff] token is even extracted - this
     * function is the ONE place that decides an App Link is worth acting on
     * at all; it never trusts the URL's mere well-formedness as a signal of
     * anything.
     */
    fun resolveAppLinkUrl(url: String): ActivationInputResolution {
        val parsed = try {
            java.net.URI(url)
        } catch (e: java.net.URISyntaxException) {
            return ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_SCHEME)
        }
        if (!"https".equals(parsed.scheme, ignoreCase = true)) {
            return ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_SCHEME)
        }
        if (parsed.host != PRODUCTION_ACTIVATION_HOST) {
            return ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_HOST)
        }
        val path = parsed.path.orEmpty()
        if (!path.startsWith(ACTIVATION_PATH_PREFIX)) {
            return ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_WRONG_PATH)
        }
        val token = path.removePrefix(ACTIVATION_PATH_PREFIX)
        if (!TOKEN_FORMAT.matches(token)) {
            return ActivationInputResolution.Rejected(ActivationInputRejectionReason.APPLINK_MALFORMED_TOKEN)
        }
        return ActivationInputResolution.NeedsHandoff(token)
    }
}

/**
 * Adapter-level UI state ONLY - never a crypto/trust verdict (that stays
 * exclusively in [ActivationPackageUiState], unchanged). Exists so a file/QR/
 * App Link adapter can surface "this input's own shape was unusable" or
 * "this needs a server feature that doesn't exist yet" without inventing a
 * new [ActivationPackageRejectionKind] for something the EXISTING crypto
 * pipeline never even saw.
 */
sealed class ActivationInputAdapterUiState {
    object Idle : ActivationInputAdapterUiState()
    data class Rejected(val reason: ActivationInputRejectionReason) : ActivationInputAdapterUiState()

    /**
     * An App Link/QR resolved to a well-formed one-time [token], but no
     * backend endpoint exists yet to exchange it for a package (see
     * docs/ACTIVATION_HANDOFF_CONTRACT.md) - this is NEVER treated as
     * trusted or redeemable; it is purely "not yet supported", surfaced
     * exactly like any other unavailable feature.
     */
    data class HandoffNotSupported(val token: String) : ActivationInputAdapterUiState()
}

fun ActivationInputAdapterUiState.toDisplayMessage(): String? = when (this) {
    ActivationInputAdapterUiState.Idle -> null
    is ActivationInputAdapterUiState.HandoffNotSupported -> "This activation link requires a feature that isn't available yet. Use a file or paste the activation package instead."
    is ActivationInputAdapterUiState.Rejected -> when (reason) {
        ActivationInputRejectionReason.FILE_EMPTY, ActivationInputRejectionReason.FILE_UNREADABLE ->
            "Couldn't read that file. Choose a valid activation package file."
        ActivationInputRejectionReason.QR_EMPTY, ActivationInputRejectionReason.QR_UNRECOGNIZED ->
            "That QR code isn't a recognized activation code."
        ActivationInputRejectionReason.APPLINK_WRONG_SCHEME,
        ActivationInputRejectionReason.APPLINK_WRONG_HOST,
        ActivationInputRejectionReason.APPLINK_WRONG_PATH,
        ActivationInputRejectionReason.APPLINK_MALFORMED_TOKEN,
        -> "That activation link isn't recognized."
    }
}
