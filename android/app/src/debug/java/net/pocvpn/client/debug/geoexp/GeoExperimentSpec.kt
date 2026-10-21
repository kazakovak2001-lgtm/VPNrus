package net.pocvpn.client.debug.geoexp

import org.json.JSONArray
import org.json.JSONObject

/**
 * M1 debug-only experiment - the fixed, pure part of the GeoIP/Geosite
 * database-loading harness: which cases and modes exist, the exact Xray
 * configs they start the core with, how a start failure is parsed and how
 * each (case, mode) outcome is judged.
 *
 * Safety shape of EVERY config built here (no exceptions): a single
 * `blackhole` outbound, NO inbound (so no `tun`, no listener), no `dns`,
 * `api`, `metrics` or `observatory` section and no `freedom` outbound. The
 * only variable part is one routing rule whose target is that same
 * blackhole outbound. Nothing here can carry user traffic. No profile,
 * credential, server address or key is read or written by this file.
 *
 * What this experiment does and does NOT establish (read before trusting a
 * verdict):
 * - The `mobasset` fallback of the AndroidLibXrayLite wrapper is NOT tested.
 *   By static analysis of the pinned sources it is unreachable: Xray-core's
 *   `getAssetFileLocation` returns the `os.Stat` error before the wrapper's
 *   `NewFileReader` (which holds the fallback) is ever called. That is a
 *   static conclusion about upstream code, not a runtime verification; the
 *   [Mode.NEGATIVE_CONTROL] cases only observe what really happens.
 * - Success in [Mode.NEGATIVE_CONTROL] is never evidence of `mobasset`.
 *
 * What each piece of evidence confirms - and nothing more:
 * - SHA-256 + size of the staged copy ([GeoAssetStaging]): the copy in
 *   `xray-assets` is byte-identical to the APK asset at the time of copying.
 *   It says nothing about whether the file is a valid database, contains any
 *   given code, or that Xray read or parsed it.
 * - E2/E3 ([Mode.COPIED_ASSETS]), core started: the rule was accepted. The
 *   code header was located in the copied file, but opening versus parsing of
 *   the database BODY is not distinguishable here, so those cases are
 *   INCONCLUSIVE by design (see [DATA_USE_PROBE_PROPOSAL]). They are NOT proof
 *   that the body of the database was loaded.
 * - E4/E5 ([Mode.COPIED_ASSETS]) PASS: Xray opened the copied file and its
 *   header scan reached a clean end of file without finding the (unknown)
 *   code. It is a textual conclusion drawn from the upstream error format, not
 *   a formal proof, and it proves nothing about the body of any record.
 * - E6 / [Mode.NEGATIVE_CONTROL] PASS: the file was reported absent, not
 *   unreadable for another reason.
 * The error formats parsed here were derived from reading the pinned Xray
 * sources (`common/errors` Error(): `message > inner`; `common/geodata`
 * `checkFile`/`loadFile`); they have not been observed on a device yet. A
 * different real format therefore ends as FAIL (never PASS) with the full text
 * recorded.
 *
 * Pure (no Android types, no native library) so the judgement is unit-testable
 * on the JVM; not wired into any production path.
 */
internal enum class GeoCase(val id: String) {
    /** Preconditions and staging plan only - the core is never started, nothing is written. */
    E0("E0"),
    /** Baseline: blackhole only, no routing section. */
    E1("E1"),
    /** Valid GeoIP code (default `private`). */
    E2("E2"),
    /** Valid Geosite code (default `google`). */
    E3("E3"),
    /** Unknown GeoIP code. */
    E4("E4"),
    /** Unknown Geosite code. */
    E5("E5"),
    /** `ext:` rule naming a database file that does not exist - start must fail. */
    E6("E6");

    /** The database file a case reads (null = none). */
    val databaseFile: String?
        get() = when (this) {
            E2, E4 -> GeoExperimentSpec.GEOIP_FILE
            E3, E5 -> GeoExperimentSpec.GEOSITE_FILE
            else -> null
        }

    companion object {
        fun parse(id: String?): GeoCase? = entries.firstOrNull { it.id == id }
    }
}

/** Mutually exclusive, recorded separately; always passed explicitly (never defaulted). */
internal enum class Mode {
    /** No copy into `xray-assets`; the database files must be absent there. Nothing is written by the harness. */
    NEGATIVE_CONTROL,

    /** `geoip.dat` / `geosite.dat` are first copied (verified) from the APK assets into `xray-assets`. */
    COPIED_ASSETS;

    companion object {
        fun parse(id: String?): Mode? = entries.firstOrNull { it.name == id }
    }
}

internal enum class Verdict {
    /** The observed outcome matches the case's documented expectation for this mode. */
    PASS,

    /** The observed outcome contradicts the documented expectation. */
    FAIL,

    /** The run cannot establish what the case is about (see the reason in the result). */
    INCONCLUSIVE,

    /** Staging the files failed or was unsafe - NOT an Xray result; the core was not started. */
    PREP_ERROR,

    /** A safety precondition failed; nothing was started and nothing was written. */
    REFUSED,

    /** An unexpected error in the harness itself (not an Xray start result); the case did not complete. */
    HARNESS_ERROR,
}

internal enum class GeoErrorClass { NONE, OPEN_FAILED, DATA_CORRUPT, CODE_NOT_FOUND, SYNTAX, OTHER }

internal object GeoExperimentSpec {

    const val OUTBOUND_TAG = "geoexp-blackhole"
    const val GEOIP_FILE = "geoip.dat"
    const val GEOSITE_FILE = "geosite.dat"
    const val DEFAULT_GEOIP_CODE = "private"
    const val DEFAULT_GEOSITE_CODE = "google"
    const val UNKNOWN_CODE = "NOSUCHCODE"
    const val MISSING_FILE = "nosuchfile.dat"

    /** The database files the harness stages / requires to be absent in [Mode.NEGATIVE_CONTROL]. */
    val DATABASE_FILES: List<String> = listOf(GEOIP_FILE, GEOSITE_FILE)

    /**
     * Not implemented. A single extra case that would turn "the code was located" into "the
     * database body was parsed during startLoop": a harness-owned synthetic `.dat` containing one
     * record whose header (code) is valid but whose body is truncated protobuf, referenced via
     * `ext:<file>:<CODE>`. If startLoop then fails with a data-corruption error ("unmarshal"), the
     * body is read and parsed at startLoop; if it starts, parsing is lazy and E2/E3 only prove
     * opening. Needs its own approval because it writes one more (harness-named) file.
     */
    const val DATA_USE_PROBE_PROPOSAL = "E7 synthetic truncated-body record (not implemented)"

    private val SAFE_CODE = Regex("^[A-Za-z0-9_-]{1,40}$")

    /** A code override is only accepted for E2/E3 and only in this restricted alphabet; null = use the default. */
    fun sanitizeCode(raw: String?): String? = raw?.takeIf { SAFE_CODE.matches(it) }

    /** True for the cases that need the real database files (and therefore staging in [Mode.COPIED_ASSETS]). */
    fun needsDatabases(case: GeoCase): Boolean = case.databaseFile != null

    /** The config JSON for [case], or null for E0 (which never starts the core). */
    fun config(case: GeoCase, codeOverride: String? = null): String? {
        val rule: JSONObject? = when (case) {
            GeoCase.E0 -> return null
            GeoCase.E1 -> null
            GeoCase.E2 -> ipRule("geoip:${codeOverride ?: DEFAULT_GEOIP_CODE}")
            GeoCase.E3 -> domainRule("geosite:${codeOverride ?: DEFAULT_GEOSITE_CODE}")
            GeoCase.E4 -> ipRule("geoip:$UNKNOWN_CODE")
            GeoCase.E5 -> domainRule("geosite:$UNKNOWN_CODE")
            GeoCase.E6 -> ipRule("ext:$MISSING_FILE:private")
        }
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "debug").put("access", "none"))
        // Required: the pinned wrapper type-asserts the stats feature after core.New().
        root.put("stats", JSONObject())
        root.put(
            "outbounds",
            JSONArray().put(JSONObject().put("tag", OUTBOUND_TAG).put("protocol", "blackhole")),
        )
        if (rule != null) {
            root.put(
                "routing",
                JSONObject().put("domainStrategy", "AsIs").put("rules", JSONArray().put(rule)),
            )
        }
        return root.toString()
    }

    private fun ipRule(entry: String): JSONObject =
        JSONObject().put("type", "field").put("ip", JSONArray().put(entry)).put("outboundTag", OUTBOUND_TAG)

    private fun domainRule(entry: String): JSONObject =
        JSONObject().put("type", "field").put("domain", JSONArray().put(entry)).put("outboundTag", OUTBOUND_TAG)

    // ---- error parsing -------------------------------------------------------------------------
    // Xray's errors.Error.Error() joins a message and its inner error with " > " (outermost first):
    //   "<outer rule wrapper> > geodata: failed to check code NOSUCHCODE from geoip.dat > EOF"
    // (Xray-core common/errors Error(), common/geodata checkFile/loadFile.) The exception message
    // crossing JNI is that string. Everything below works on the " > " chain, never on a bare contains().

    private const val CHAIN_SEPARATOR = " > "

    /** Substrings (lower case) that mark a damaged or truncated database read, wherever they appear. */
    private val CORRUPTION_MARKERS = listOf("unmarshal", "varint overflow", "invalid body length", "unexpected eof")

    private val CODE_PHRASE = Regex("""failed to (check|load) code\s+(\S+)\s+from\s+(\S+)""", RegexOption.IGNORE_CASE)
    private val OPEN_PHRASE = Regex("""failed to open\s+(\S+)""", RegexOption.IGNORE_CASE)

    private fun chain(message: String): List<String> = message.split(CHAIN_SEPARATOR).map { it.trim() }

    fun hasCorruptionMarker(message: String?): Boolean {
        val m = message?.lowercase() ?: return false
        return CORRUPTION_MARKERS.any { it in m }
    }

    /** `failed to open <file>` and whether its inner cause says the file does not exist (not e.g. a permission error). */
    data class OpenFailure(val file: String, val absent: Boolean)

    fun parseOpenFailure(message: String?): OpenFailure? {
        if (message == null) return null
        val segments = chain(message)
        val index = segments.indexOfFirst { OPEN_PHRASE.containsMatchIn(it) }
        if (index < 0) return null
        val file = OPEN_PHRASE.find(segments[index])!!.groupValues[1]
        val causes = segments.drop(index + 1).map { it.lowercase() }
        val absent = causes.any { "no such file or directory" in it } && causes.none { "permission denied" in it }
        return OpenFailure(file, absent)
    }

    /**
     * `failed to check|load code <CODE> from <file>`. [cleanEof] is true only when the single inner
     * cause is exactly `EOF` (the file was read to its clean end without finding the code); a
     * truncated read (`unexpected EOF`) or any other cause is NOT a clean EOF. [corrupt] is true if
     * any corruption marker appears anywhere in the message.
     */
    data class CodeNotFound(val code: String, val file: String, val cleanEof: Boolean, val corrupt: Boolean)

    fun parseCodeNotFound(message: String?): CodeNotFound? {
        if (message == null) return null
        val segments = chain(message)
        val index = segments.indexOfFirst { CODE_PHRASE.containsMatchIn(it) }
        if (index < 0) return null
        val match = CODE_PHRASE.find(segments[index])!!
        val after = segments.drop(index + 1)
        return CodeNotFound(
            code = match.groupValues[2],
            file = match.groupValues[3],
            cleanEof = after.size == 1 && after[0] == "EOF",
            corrupt = hasCorruptionMarker(message),
        )
    }

    /**
     * Coarse classification of a start failure for the result file. Order matters: a damaged-input
     * marker wins over the "failed to check/load code" wrapper that upstream puts around read errors.
     */
    fun classify(message: String?): GeoErrorClass {
        if (message == null) return GeoErrorClass.NONE
        val m = message.lowercase()
        return when {
            OPEN_PHRASE.containsMatchIn(message) -> GeoErrorClass.OPEN_FAILED
            hasCorruptionMarker(message) -> GeoErrorClass.DATA_CORRUPT
            CODE_PHRASE.containsMatchIn(message) -> GeoErrorClass.CODE_NOT_FOUND
            "syntax error" in m || "empty code" in m || "empty file" in m -> GeoErrorClass.SYNTAX
            else -> GeoErrorClass.OTHER
        }
    }

    // ---- judgement -----------------------------------------------------------------------------

    /** What actually happened when the case ran (all fields measured, none assumed). */
    data class Observation(
        /** Non-null = a safety precondition failed; nothing was started or written. */
        val refusedReason: String? = null,
        /** Non-null = staging was unsafe or failed; the core was not started. */
        val prepError: String? = null,
        /** Non-null = an unexpected harness error (core env init, result I/O...) - not an Xray start result. */
        val harnessError: String? = null,
        val startedOk: Boolean = false,
        val runningAfterStart: Boolean = false,
        val runningAfterStop: Boolean = false,
        /** stopLoop() itself threw. */
        val stopFailed: Boolean = false,
        /** The startLoop exception's own message (not the stack trace). */
        val errorMessage: String? = null,
    )

    data class Judgement(val verdict: Verdict, val expectation: String, val reason: String)

    /** The documented expectation and verdict per (case, mode). A general or unmatched error is never a PASS. */
    fun judge(case: GeoCase, mode: Mode, observed: Observation): Judgement {
        val expectation = expectation(case, mode)
        observed.refusedReason?.let { return Judgement(Verdict.REFUSED, expectation, it) }
        observed.prepError?.let { return Judgement(Verdict.PREP_ERROR, expectation, it) }
        observed.harnessError?.let { return Judgement(Verdict.HARNESS_ERROR, expectation, it) }
        val message = observed.errorMessage
        val ranAndStopped = observed.startedOk && observed.runningAfterStart && !observed.runningAfterStop && !observed.stopFailed

        return when (case) {
            GeoCase.E0 -> Judgement(Verdict.PASS, expectation, "preconditions and staging plan are safe; core not started")
            GeoCase.E1 ->
                if (ranAndStopped) Judgement(Verdict.PASS, expectation, "blackhole-only config started and stopped")
                else Judgement(Verdict.FAIL, expectation, "baseline: ${describeOutcome(observed)}")
            GeoCase.E6 -> judgeOpenFailure(expectation, observed, MISSING_FILE)
            GeoCase.E2, GeoCase.E3, GeoCase.E4, GeoCase.E5 -> {
                val file = case.databaseFile!!
                when {
                    mode == Mode.NEGATIVE_CONTROL ->
                        if (observed.startedOk) {
                            Judgement(
                                Verdict.INCONCLUSIVE, expectation,
                                "core started without staged databases: contradicts the static prediction; " +
                                    "this is NOT evidence of mobasset (the file may have been found by another path)",
                            )
                        } else {
                            judgeOpenFailure(expectation, observed, file)
                        }
                    case == GeoCase.E2 || case == GeoCase.E3 -> judgeValidCode(expectation, observed, file, ranAndStopped)
                    else -> judgeUnknownCode(expectation, observed, file)
                }
            }
        }
    }

    private fun describeOutcome(o: Observation): String = when {
        !o.startedOk -> "start failed: ${classify(o.errorMessage).name}"
        !o.runningAfterStart -> "startLoop returned but the core reports it is not running"
        o.runningAfterStop || o.stopFailed ->
            "core started, but stopLoop did not cleanly stop it (runningAfterStop=${o.runningAfterStop}, stopLoopThrew=${o.stopFailed})"
        else -> "core started and stopped"
    }

    /** PASS only for `failed to open <file>` naming [file] whose inner cause is "no such file or directory". */
    private fun judgeOpenFailure(expectation: String, o: Observation, file: String): Judgement {
        if (o.startedOk) return Judgement(Verdict.FAIL, expectation, "core started although $file is absent")
        val open = parseOpenFailure(o.errorMessage)
            ?: return Judgement(Verdict.FAIL, expectation, "no 'failed to open' error; got ${classify(o.errorMessage).name}")
        return when {
            !open.file.equals(file, ignoreCase = true) -> Judgement(Verdict.FAIL, expectation, "open failure names ${open.file}, expected $file")
            !open.absent -> Judgement(Verdict.FAIL, expectation, "open failure for $file is not an absent-file error (cause is not 'no such file or directory', or access was denied)")
            else -> Judgement(Verdict.PASS, expectation, "$file reported absent (open failure with 'no such file or directory'), as predicted by static analysis")
        }
    }

    /** E2/E3 in COPIED_ASSETS: a clean start is INCONCLUSIVE for data use; every failure is a FAIL. */
    private fun judgeValidCode(expectation: String, o: Observation, file: String, ranAndStopped: Boolean): Judgement = when {
        ranAndStopped ->
            Judgement(
                Verdict.INCONCLUSIVE, expectation,
                "core started and stopped: the rule was accepted with the copied $file, but opening versus parsing of the " +
                    "body is not distinguishable in this run (see $DATA_USE_PROBE_PROPOSAL)",
            )
        o.startedOk -> Judgement(Verdict.FAIL, expectation, describeOutcome(o))
        else -> Judgement(Verdict.FAIL, expectation, "start failed with a valid code: ${classify(o.errorMessage).name}")
    }

    /** E4/E5 in COPIED_ASSETS: PASS only for a clean-EOF "code not found" naming the unknown code and the right file. */
    private fun judgeUnknownCode(expectation: String, o: Observation, file: String): Judgement {
        if (o.startedOk) return Judgement(Verdict.FAIL, expectation, "unknown code silently accepted - start succeeded")
        if (parseOpenFailure(o.errorMessage) != null) {
            return Judgement(Verdict.FAIL, expectation, "open failure although the files were staged - copy not effective")
        }
        val nf = parseCodeNotFound(o.errorMessage)
            ?: return Judgement(Verdict.FAIL, expectation, "not a 'code not found' error: ${classify(o.errorMessage).name}")
        return when {
            nf.corrupt -> Judgement(Verdict.FAIL, expectation, "read/parse damage marker present - not evidence of an absent code")
            !nf.code.equals(UNKNOWN_CODE, ignoreCase = true) -> Judgement(Verdict.FAIL, expectation, "error names code ${nf.code}, expected $UNKNOWN_CODE")
            !nf.file.equals(file, ignoreCase = true) -> Judgement(Verdict.FAIL, expectation, "error names file ${nf.file}, expected $file")
            !nf.cleanEof -> Judgement(Verdict.FAIL, expectation, "inner cause is not a clean EOF")
            else -> Judgement(Verdict.PASS, expectation, "$file opened and read to a clean end without finding $UNKNOWN_CODE; unknown code rejected")
        }
    }

    /** Human-readable expectation, recorded verbatim in every result. */
    fun expectation(case: GeoCase, mode: Mode): String = when (case) {
        GeoCase.E0 -> "preconditions hold and the staging plan is safe; core not started"
        GeoCase.E1 -> "start OK (blackhole only), stop OK"
        GeoCase.E6 -> "start fails: 'failed to open $MISSING_FILE' with cause 'no such file or directory'"
        GeoCase.E2, GeoCase.E3 ->
            if (mode == Mode.NEGATIVE_CONTROL) "start fails: 'failed to open ${case.databaseFile}' with cause 'no such file or directory' (static prediction)"
            else "start OK; INCONCLUSIVE for data use (open vs parse not distinguished)"
        GeoCase.E4, GeoCase.E5 ->
            if (mode == Mode.NEGATIVE_CONTROL) "start fails: 'failed to open ${case.databaseFile}' with cause 'no such file or directory' (static prediction)"
            else "start fails: 'failed to check|load code $UNKNOWN_CODE from ${case.databaseFile}' with a clean EOF cause"
    }
}
