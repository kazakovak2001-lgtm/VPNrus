package net.pocvpn.client.diagnostics.fieldtest

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.TimeUnit

/**
 * Field test - the app's own log buffer (Android only shows an app its own
 * UID's lines: Kotlin layers, AWG/Xray natives, the Hysteria2/sslocal child
 * process output the launchers forward to logcat). Every line goes through
 * [LogSanitizer] before it can reach a report.
 */
object FieldLogs {

    suspend fun collect(maxLines: Int = 5_000, timeoutMs: Long = 10_000): List<String> = withContext(Dispatchers.IO) {
        withTimeoutOrNull(timeoutMs) {
            try {
                val process = ProcessBuilder("logcat", "-d", "-v", "threadtime", "-t", maxLines.toString())
                    .redirectErrorStream(true)
                    .start()
                val lines = process.inputStream.bufferedReader().readLines()
                process.waitFor(2, TimeUnit.SECONDS)
                lines.takeLast(maxLines).map(LogSanitizer::sanitize)
            } catch (e: Exception) {
                listOf("log collection failed: ${describeError(e)}")
            }
        } ?: listOf("log collection timed out")
    }
}

/**
 * Pure redaction for log lines that leave the device. Removes anything that
 * can authenticate or identify: UUIDs (VLESS ids, activation ids),
 * WireGuard/AWG keys, long base64/hex tokens (credentials, PSKs, envelopes),
 * key=value secrets and e-mail addresses. Keeps what is needed to debug:
 * tags, states, error texts, ports, our own gateway addresses.
 */
object LogSanitizer {
    private val rules: List<Pair<Regex, String>> = listOf(
        Regex("""(?i)\b(password|passwd|pass|secret|token|credential|auth|authorization|private[_ ]?key|psk|uuid|id_token)\b(\s*[:=]\s*)("[^"]*"|\S+)""") to "$1$2<redacted>",
        Regex("""\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b""") to "<uuid>",
        Regex("""(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=""") to "<key>",
        Regex("""\b[0-9a-fA-F]{32,}\b""") to "<hex>",
        Regex("""(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{40,}={0,2}""") to "<token>",
        Regex("""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b""") to "<email>",
        Regex("""nova-activation:\S+""") to "nova-activation:<redacted>",
    )

    fun sanitize(line: String): String = rules.fold(line) { acc, (regex, replacement) -> regex.replace(acc, replacement) }
}
