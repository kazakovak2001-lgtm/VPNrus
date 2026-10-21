package net.pocvpn.client.debug.geoexp

import org.json.JSONArray
import org.json.JSONObject

/**
 * M1 debug-only experiment - the fixed, pure part of the GeoIP/Geosite
 * database-loading harness: which cases exist, the exact Xray configs they
 * start the core with, and how a start failure is classified and judged.
 *
 * Safety shape of EVERY config built here (no exceptions): a single
 * `blackhole` outbound, NO inbound (so no `tun`, no listener), no `dns`,
 * `api`, `metrics` or `observatory` section and no `freedom` outbound. The
 * only variable part is one routing rule whose target is that same
 * blackhole outbound. Nothing here can carry user traffic, and a rule can
 * never route anywhere but the blackhole. No profile, credential, server
 * address or key is read or written by this file.
 *
 * Pure (no Android types, no native library) so the judgement below is
 * readable in isolation; it is not wired into any production path.
 */
internal enum class GeoCase(val id: String) {
    /** Preconditions only - the core is never started. */
    E0("E0"),
    /** Baseline: blackhole only, no routing section. */
    E1("E1"),
    /** Valid GeoIP code (default `private`). */
    E2("E2"),
    /** Valid Geosite code (default `google`). */
    E3("E3"),
    /** Unknown GeoIP code - start must fail. */
    E4("E4"),
    /** Unknown Geosite code - start must fail. */
    E5("E5"),
    /** `ext:` rule naming a database file that does not exist - start must fail. */
    E6("E6");

    companion object {
        fun parse(id: String?): GeoCase? = entries.firstOrNull { it.id == id }
    }
}

internal enum class GeoErrorClass { NONE, OPEN_FAILED, CODE_NOT_FOUND, SYNTAX, DATA_CORRUPT, OTHER }

internal object GeoExperimentSpec {

    const val OUTBOUND_TAG = "geoexp-blackhole"
    const val DEFAULT_GEOIP_CODE = "private"
    const val DEFAULT_GEOSITE_CODE = "google"
    const val UNKNOWN_CODE = "NOSUCHCODE"
    const val MISSING_FILE = "nosuchfile.dat"

    /** The database files the harness requires to be absent from `xray-assets` (so a read can only come from the APK assets via mobasset). */
    val DATABASE_FILES: List<String> = listOf("geoip.dat", "geosite.dat")

    private val SAFE_CODE = Regex("^[A-Za-z0-9_-]{1,40}$")

    /** A code override is only accepted for E2/E3 and only in this restricted alphabet; null = use the default. */
    fun sanitizeCode(raw: String?): String? = raw?.takeIf { SAFE_CODE.matches(it) }

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

    /**
     * Classifies a start failure by the pinned Xray/wrapper error text
     * (Xray-core 5ca6f4b common/geodata: rule_parser.go / geodat_loader.go).
     * Text matching is the only available discriminator - the native error
     * crosses JNI as a plain exception message.
     */
    fun classify(message: String?): GeoErrorClass {
        if (message == null) return GeoErrorClass.NONE
        val m = message.lowercase()
        return when {
            "failed to open" in m -> GeoErrorClass.OPEN_FAILED
            "failed to load code" in m || "failed to check code" in m -> GeoErrorClass.CODE_NOT_FOUND
            "syntax error" in m || "empty code" in m || "empty file" in m -> GeoErrorClass.SYNTAX
            "unmarshal" in m || "varint overflow" in m || "invalid body length" in m -> GeoErrorClass.DATA_CORRUPT
            else -> GeoErrorClass.OTHER
        }
    }

    /** What actually happened when the case ran (all fields measured, none assumed). */
    data class Observation(
        val preconditionsOk: Boolean,
        val startedOk: Boolean,
        val runningAfterStart: Boolean,
        val runningAfterStop: Boolean,
        val errorMessage: String?,
    )

    /** PASS/FAIL rule per case, exactly the criteria of the M1 experiment table. */
    fun verdict(case: GeoCase, observed: Observation): Boolean {
        if (!observed.preconditionsOk) return false
        val errorClass = classify(observed.errorMessage)
        return when (case) {
            GeoCase.E0 -> true
            GeoCase.E1, GeoCase.E2, GeoCase.E3 ->
                observed.startedOk && observed.runningAfterStart && !observed.runningAfterStop
            GeoCase.E4, GeoCase.E5 ->
                !observed.startedOk && !observed.runningAfterStart && errorClass == GeoErrorClass.CODE_NOT_FOUND &&
                    observed.errorMessage?.contains(UNKNOWN_CODE, ignoreCase = true) == true
            GeoCase.E6 ->
                !observed.startedOk && !observed.runningAfterStart && errorClass == GeoErrorClass.OPEN_FAILED &&
                    observed.errorMessage?.contains(MISSING_FILE, ignoreCase = true) == true
        }
    }
}
