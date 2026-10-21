package net.pocvpn.client.debug.geoexp

import android.app.Activity
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.util.Log
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M1 debug-only manual entry point: runs EXACTLY ONE case (E0..E6) of the
 * GeoIP/Geosite database-loading experiment inside the `:xray` process, via
 * the production [LibXrayCoreRuntime] (so the real `go.Seq.setContext` +
 * `initCoreEnv` + `startLoop` path is the one under test), then writes one
 * JSON result file and one log line. Lives in the `debug` source set only -
 * absent from release builds, like [net.pocvpn.client.debug.XrayDiagnosticsActivity].
 *
 * Launch (explicit shell command, after a separate approval):
 * `am start -n net.pocvpn.client/net.pocvpn.client.debug.geoexp.GeoDbExperimentActivity --es case E2`
 * Optional `--es code <CODE>` overrides the GeoIP code of E2 / Geosite code
 * of E3 only (restricted alphabet, see [GeoExperimentSpec.sanitizeCode]).
 *
 * What it NEVER does: establish a VPN or a TUN (`startLoop` gets tunFd 0 and
 * the config has no inbound), open a socket or HTTP connection (no network
 * API of any kind is used - the only network-adjacent calls are the
 * read-only [ConnectivityManager] capability query and the app's own
 * [TrafficStats] byte counters), read or write a profile, credential or
 * server address, or use a `freedom`/direct outbound. See [GeoExperimentSpec].
 *
 * One case per process: if this process already ran a case the harness
 * refuses (FAIL, nothing started) - force-stop the app between cases. The
 * process is deliberately NOT killed by the harness: it may share `:xray`
 * with a live production session, which the preconditions rule out but the
 * harness must not be the thing that proves it wrong.
 */
class GeoDbExperimentActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val case = GeoCase.parse(intent?.getStringExtra(EXTRA_CASE))
        if (savedInstanceState != null || case == null) {
            Log.w(TAG, "GEOEXP|refused|reason=${if (case == null) "unknown-or-missing-case" else "recreated"}")
            finishAndRemoveTask()
            return
        }
        val codeOverride = GeoExperimentSpec.sanitizeCode(intent.getStringExtra(EXTRA_CODE))
        val appContext = applicationContext
        Thread({
            try {
                val result = runCase(appContext, case, codeOverride)
                persistAndLog(appContext, case, result)
            } catch (t: Throwable) {
                Log.e(TAG, "GEOEXP|case=${case.id}|harness-error=${oneLine(t.toString())}")
            } finally {
                runOnUiThread { finishAndRemoveTask() }
            }
        }, "geoexp-${case.id}").start()
    }

    private fun runCase(context: Context, case: GeoCase, codeOverride: String?): JSONObject {
        val out = JSONObject()
            .put("case", case.id)
            .put("startedAtEpochMs", System.currentTimeMillis())
            .put("sdk", Build.VERSION.SDK_INT)
            .put("pid", Process.myPid())
            .put("uid", Process.myUid())
        val processName = readProcessName()
        out.put("processName", processName)
        codeOverride?.let { out.put("codeOverride", it) }

        val xrayAssetsDir = File(context.noBackupFilesDir, "xray-assets")
        val runtime = LibXrayCoreRuntime()

        // ---- preconditions (all blocking except the informational ones) ----
        val preconditions = JSONObject()
        val inXrayProcess = processName.endsWith(":xray")
        val freshProcess = !CASE_ALREADY_RUN.getAndSet(true)
        val vpnActive = isAnyVpnActive(context)
        val assetsBefore = listDir(xrayAssetsDir)
        val xrayAssetsClean = GeoExperimentSpec.DATABASE_FILES.none { it in assetsBefore }
        val apkAssets = try { context.assets.list("")?.toList().orEmpty() } catch (t: Throwable) { emptyList() }
        val apkHasDatabases = GeoExperimentSpec.DATABASE_FILES.all { it in apkAssets }
        preconditions
            .put("inXrayProcess", inXrayProcess)
            .put("freshProcess", freshProcess)
            .put("noVpnActive", vpnActive == false)
            .put("vpnQueryResult", vpnActive?.toString() ?: "unknown")
            .put("xrayAssetsHasNoDatabases", xrayAssetsClean)
            .put("apkAssetsHaveDatabases", apkHasDatabases)
            .put("coreNotRunning", !runtime.isRunning)
        out.put("xrayAssetsBefore", JSONArray(assetsBefore))
        out.put("preconditions", preconditions)
        val preconditionsOk = inXrayProcess && freshProcess && vpnActive == false && xrayAssetsClean &&
            apkHasDatabases && !runtime.isRunning
        out.put("preconditionsOk", preconditionsOk)

        var startedOk = false
        var runningAfterStart = false
        var runningAfterStop = false
        var errorMessage: String? = null
        var ran = false

        val config = GeoExperimentSpec.config(case, codeOverride)
        if (preconditionsOk && config != null) {
            ran = true
            val uid = Process.myUid()
            val before = snapshot(uid)
            val initStart = SystemClock.elapsedRealtimeNanos()
            runtime.ensureCoreEnvInitialized(context)
            val initMs = (SystemClock.elapsedRealtimeNanos() - initStart) / 1_000_000.0
            val afterInit = snapshot(uid)
            val startNanos = SystemClock.elapsedRealtimeNanos()
            try {
                runtime.startLoop(config, 0)
                startedOk = true
            } catch (t: Throwable) {
                errorMessage = fullError(t)
            }
            val startMs = (SystemClock.elapsedRealtimeNanos() - startNanos) / 1_000_000.0
            runningAfterStart = runtime.isRunning
            val afterStart = snapshot(uid)
            var stopError: String? = null
            try {
                runtime.stopLoop()
            } catch (t: Throwable) {
                stopError = fullError(t)
            }
            runningAfterStop = runtime.isRunning
            val afterStop = snapshot(uid)
            out.put("initCoreEnvMs", initMs)
            out.put("startLoopMs", startMs)
            out.put("snapshotBefore", before)
            out.put("snapshotAfterInit", afterInit)
            out.put("snapshotAfterStart", afterStart)
            out.put("snapshotAfterStop", afterStop)
            out.put("uidTxDeltaBytes", delta(before, afterStop, "uidTxBytes"))
            out.put("uidRxDeltaBytes", delta(before, afterStop, "uidRxBytes"))
            out.put("xrayAssetsAfter", JSONArray(listDir(xrayAssetsDir)))
            stopError?.let { out.put("stopError", it) }
        }

        val observation = GeoExperimentSpec.Observation(
            preconditionsOk = preconditionsOk,
            startedOk = startedOk,
            runningAfterStart = runningAfterStart,
            runningAfterStop = runningAfterStop,
            errorMessage = errorMessage,
        )
        val pass = GeoExperimentSpec.verdict(case, observation)
        out.put("ran", ran)
        out.put("startedOk", startedOk)
        out.put("runningAfterStart", runningAfterStart)
        out.put("runningAfterStop", runningAfterStop)
        out.put("errorClass", GeoExperimentSpec.classify(errorMessage).name)
        errorMessage?.let { out.put("error", it) }
        out.put("verdict", if (pass) "PASS" else "FAIL")
        return out
    }

    private fun persistAndLog(context: Context, case: GeoCase, result: JSONObject) {
        val dir = File(context.noBackupFilesDir, "geoexp").apply { mkdirs() }
        // Never overwrite an earlier result: pick the first free name.
        var file: File
        var n = 0
        do {
            file = File(dir, "geoexp-${case.id}-${result.optLong("startedAtEpochMs")}${if (n == 0) "" else "-$n"}.json")
            n++
        } while (!file.createNewFile())
        file.writeText(result.toString(2), Charsets.UTF_8)
        Log.i(
            TAG,
            "GEOEXP|case=${case.id}|verdict=${result.optString("verdict")}|ran=${result.optBoolean("ran")}" +
                "|errorClass=${result.optString("errorClass")}|startLoopMs=${result.opt("startLoopMs")}" +
                "|rssBeforeKb=${result.optJSONObject("snapshotBefore")?.opt("vmRssKb")}" +
                "|rssAfterStartKb=${result.optJSONObject("snapshotAfterStart")?.opt("vmRssKb")}" +
                "|hwmAfterStartKb=${result.optJSONObject("snapshotAfterStart")?.opt("vmHwmKb")}" +
                "|uidTxDelta=${result.opt("uidTxDeltaBytes")}|uidRxDelta=${result.opt("uidRxDeltaBytes")}" +
                "|file=${file.name}",
        )
        result.optString("error").takeIf { it.isNotEmpty() }?.let { Log.i(TAG, "GEOEXP|case=${case.id}|error=${oneLine(it)}") }
    }

    /** Read-only. null = could not be determined (treated as a failed precondition by the caller). */
    @Suppress("DEPRECATION")
    private fun isAnyVpnActive(context: Context): Boolean? = try {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        cm.allNetworks.any { network ->
            cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        }
    } catch (t: Throwable) {
        null
    }

    private fun snapshot(uid: Int): JSONObject {
        val status = try { File("/proc/self/status").readLines() } catch (t: Throwable) { emptyList() }
        fun kb(key: String): Long = status.firstOrNull { it.startsWith("$key:") }
            ?.substringAfter(':')?.trim()?.substringBefore(' ')?.toLongOrNull() ?: -1L
        return JSONObject()
            .put("elapsedRealtimeMs", SystemClock.elapsedRealtime())
            .put("vmRssKb", kb("VmRSS"))
            .put("vmHwmKb", kb("VmHWM"))
            .put("uidTxBytes", TrafficStats.getUidTxBytes(uid))
            .put("uidRxBytes", TrafficStats.getUidRxBytes(uid))
    }

    private fun delta(a: JSONObject, b: JSONObject, key: String): Long {
        val x = a.optLong(key, -1L)
        val y = b.optLong(key, -1L)
        return if (x < 0 || y < 0) -1L else y - x
    }

    private fun listDir(dir: File): List<String> = dir.list()?.sorted().orEmpty()

    private fun readProcessName(): String = try {
        File("/proc/self/cmdline").readBytes().takeWhile { it != 0.toByte() }.toByteArray().toString(Charsets.UTF_8)
    } catch (t: Throwable) {
        "unknown"
    }

    private fun fullError(t: Throwable): String {
        val trace = Log.getStackTraceString(t).lineSequence().take(40).joinToString("\n")
        return "${t.javaClass.name}: ${t.message}\n$trace"
    }

    private fun oneLine(s: String): String = s.replace("\r", "").replace("\n", "\\n").take(2000)

    companion object {
        private const val TAG = "GeoExp"
        const val EXTRA_CASE = "case"
        const val EXTRA_CODE = "code"

        /** Process-wide: a second case in the same process is refused (see class docs). */
        private val CASE_ALREADY_RUN = AtomicBoolean(false)
    }
}
