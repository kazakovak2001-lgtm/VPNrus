package net.pocvpn.b46harness

import java.io.File

/**
 * B46-2P - the `--config-file` payload for the minimal Hysteria2 child (see
 * `research/b46-2p-android-physical/hysteria-minimal-client/novaminimal_main.go`'s
 * `novaminimalConfig`). Deliberately has NO `toString()` override that
 * exposes [auth]/[obfsSalamander] - the default `data class` `toString()`
 * IS overridden below specifically to redact them, so accidental logging
 * (e.g. `Log.d(TAG, "$config")`) can never leak the secret. Use
 * [redactedSummary] for any intentional log line.
 */
internal data class B46HysteriaChildConfig(
    val server: String,
    val auth: String,
    val sni: String,
    val insecure: Boolean,
    val obfsSalamander: String,
    val socksListen: String,
    val protectPath: String,
) {
    /** Never includes [auth]/[obfsSalamander] - safe for Log/UI. */
    fun redactedSummary(): String =
        "server=$server sni=$sni insecure=$insecure socksListen=$socksListen " +
            "protectPath=$protectPath authSet=${auth.isNotEmpty()} obfsSet=${obfsSalamander.isNotEmpty()}"

    /** Overridden so a stray `"$config"`/`Log.d(TAG, config.toString())` cannot leak the secret either. */
    override fun toString(): String = redactedSummary()

    /**
     * Hand-built JSON, deliberately NOT using `org.json.JSONObject` - that
     * class is part of the Android framework stub jar, and under this
     * module's `testOptions.unitTests.isReturnDefaultValues` (needed for
     * `android.util.Log.*` elsewhere) its `toString()` silently returns
     * `null` in a plain-JVM unit test, a real, physically-found bug this
     * replaced (see docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md).
     * The schema is small and fixed, so a minimal, directly-testable
     * escaper is simpler and more robust than fighting the stub jar.
     */
    fun toJson(): String = buildString {
        append('{')
        appendJsonField("server", server)
        append(',')
        appendJsonField("auth", auth)
        append(',')
        appendJsonField("sni", sni)
        append(',')
        append("\"insecure\":").append(insecure)
        append(',')
        appendJsonField("obfsSalamander", obfsSalamander)
        append(',')
        appendJsonField("socksListen", socksListen)
        append(',')
        appendJsonField("protectPath", protectPath)
        append('}')
    }

    private fun StringBuilder.appendJsonField(name: String, value: String) {
        append('"').append(name).append("\":\"").append(escapeJsonString(value)).append('"')
    }
}

private fun escapeJsonString(value: String): String = buildString {
    for (c in value) {
        when (c) {
            '"' -> append("\\\"")
            '\\' -> append("\\\\")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            else -> if (c.code < 0x20) append("\\u%04x".format(c.code)) else append(c)
        }
    }
}

/**
 * Writes [config] to [file] as JSON, mode 600 (owner read/write only,
 * matching the task's app-private/mode-600 requirement) - written BEFORE
 * the mode is tightened is avoided by creating the file first with
 * [File.createNewFile] (default fairly-permissive mode) then immediately
 * restricting it via [File.setReadable]/[File.setWritable] (plain JDK
 * POSIX-permission calls - real on Android, not Android-framework-stubbed,
 * unlike `android.system.Os.chmod`, which this replaced after it proved
 * unreliable specifically under this module's plain-JVM unit test stub
 * jar), then writing content, so there is never a window where the file
 * exists world-readable with content already in it.
 */
internal fun writeChildConfigFile(file: File, config: B46HysteriaChildConfig) {
    file.delete()
    check(file.createNewFile()) { "failed to create config file at ${file.absolutePath}" }
    file.setReadable(false, false)
    file.setWritable(false, false)
    file.setReadable(true, true)
    file.setWritable(true, true)
    file.writeText(config.toJson())
}
