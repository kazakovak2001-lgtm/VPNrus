package net.pocvpn.client.diagnostics.fieldtest

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Why did the app process end last time(s)? (Unexplained `EXIT_SELF
 * status=2` exits were seen in B57 physical runs.) Android 11+ keeps a
 * per-app history of process exits with a reason code; ANRs also carry a
 * text trace. Read-only, local; included only in reports the user shares.
 */
object ExitReasons {

    fun collect(context: Context, max: Int = 20): JSONArray {
        val out = JSONArray()
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            out.put(JSONObject().put("unavailable", "requires Android 11 (API 30)"))
            return out
        }
        val am = context.getSystemService(ActivityManager::class.java) ?: return out
        val infos = try {
            am.getHistoricalProcessExitReasons(context.packageName, 0, max)
        } catch (e: Exception) {
            out.put(JSONObject().put("error", describeError(e)))
            return out
        }
        infos.forEach { info -> out.put(describe(info)) }
        return out
    }

    private fun describe(info: ApplicationExitInfo): JSONObject {
        val o = JSONObject()
            .put("timestampEpochMillis", info.timestamp)
            .put("processName", info.processName)
            .put("pid", info.pid)
            .put("reason", reasonName(info.reason))
            .put("reasonCode", info.reason)
            .put("status", info.status)
            .put("importance", info.importance)
            .put("description", info.description?.let(LogSanitizer::sanitize) ?: JSONObject.NULL)
            .put("pssKb", info.pss)
            .put("rssKb", info.rss)
        // ANR traces are text; native-crash traces are binary tombstone protos (skipped).
        if (info.reason == ApplicationExitInfo.REASON_ANR) {
            try {
                info.traceInputStream?.use { stream ->
                    val bytes = stream.readNBytesCompat(24 * 1024)
                    o.put("anrTrace", String(bytes, Charsets.UTF_8).lines().joinToString("\n") { LogSanitizer.sanitize(it) })
                }
            } catch (e: Exception) {
                o.put("anrTraceError", describeError(e))
            }
        }
        return o
    }

    internal fun reasonName(code: Int): String = when (code) {
        0 -> "UNKNOWN"; 1 -> "EXIT_SELF"; 2 -> "SIGNALED"; 3 -> "LOW_MEMORY"; 4 -> "CRASH"
        5 -> "CRASH_NATIVE"; 6 -> "ANR"; 7 -> "INITIALIZATION_FAILURE"; 8 -> "PERMISSION_CHANGE"
        9 -> "EXCESSIVE_RESOURCE_USAGE"; 10 -> "USER_REQUESTED"; 11 -> "USER_STOPPED"; 12 -> "DEPENDENCY_DIED"
        13 -> "OTHER"; 14 -> "FREEZER"; 15 -> "PACKAGE_STATE_CHANGE"; 16 -> "PACKAGE_UPDATED"
        else -> "CODE_$code"
    }

    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(4096)
        while (buffer.size() < limit) {
            val n = read(chunk, 0, minOf(chunk.size, limit - buffer.size()))
            if (n < 0) break
            buffer.write(chunk, 0, n)
        }
        return buffer.toByteArray()
    }
}

/**
 * Uncaught JVM exceptions, recorded locally (app-private files, newest 5)
 * before the process dies, then handed to the previous handler unchanged.
 * Installed from NovaVpnApplication. Nothing is sent anywhere; the records
 * only appear in a diagnostics report the user chooses to share.
 */
object CrashRecorder {
    private const val DIR = "support-diagnostics/crashes"
    private const val KEEP = 5

    fun install(context: Context) {
        val appContext = context.applicationContext
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                record(appContext.filesDir, thread.name, throwable, System.currentTimeMillis())
            } catch (_: Throwable) {
                // never let crash recording mask the original crash
            }
            previous?.uncaughtException(thread, throwable)
        }
    }

    internal fun record(filesDir: File, threadName: String, throwable: Throwable, now: Long) {
        val dir = File(filesDir, DIR).apply { mkdirs() }
        val text = buildString {
            append("time=").append(now).append('\n')
            append("thread=").append(threadName).append('\n')
            throwable.stackTraceToString().lineSequence().take(200).forEach { append(LogSanitizer.sanitize(it)).append('\n') }
        }
        File(dir, "crash-$now.txt").writeText(text)
        dir.listFiles()?.sortedByDescending { it.name }?.drop(KEEP)?.forEach { it.delete() }
    }

    fun recent(context: Context): JSONArray {
        val out = JSONArray()
        File(context.filesDir, DIR).listFiles()?.sortedByDescending { it.name }?.take(KEEP)?.forEach { f ->
            out.put(JSONObject().put("file", f.name).put("text", f.readText().take(16 * 1024)))
        }
        return out
    }
}
