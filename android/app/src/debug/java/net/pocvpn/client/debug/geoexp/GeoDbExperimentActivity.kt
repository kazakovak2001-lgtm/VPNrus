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
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.concurrent.atomic.AtomicBoolean

/**
 * M1 debug-only manual entry point: runs EXACTLY ONE (case, mode) of the
 * GeoIP/Geosite database-loading experiment inside the `:xray` process, via
 * the production [LibXrayCoreRuntime] (so the real `go.Seq.setContext` +
 * `initCoreEnv` + `startLoop` path is the one under test), and records one
 * JSON result file plus `GeoExp` log lines. Lives in the `debug` source set
 * only - absent from release builds, like
 * [net.pocvpn.client.debug.XrayDiagnosticsActivity].
 *
 * Launch (explicit shell command, after a separate approval; `mode` is
 * REQUIRED, never defaulted, so a copy can never happen by accident):
 * `am start -n net.pocvpn.client/net.pocvpn.client.debug.geoexp.GeoDbExperimentActivity --es case E2 --es mode NEGATIVE_CONTROL`
 * Optional `--es code <CODE>` overrides the GeoIP code of E2 / Geosite code
 * of E3 only (restricted alphabet, see [GeoExperimentSpec.sanitizeCode]).
 *
 * Modes (results are recorded per mode, never merged): [Mode.NEGATIVE_CONTROL]
 * writes nothing and requires the database files to be ABSENT from
 * `xray-assets`; [Mode.COPIED_ASSETS] first stages verified copies of the APK's
 * `geoip.dat` / `geosite.dat` there ([GeoAssetStaging], never overwrites or
 * deletes foreign files). Run every NEGATIVE_CONTROL case BEFORE any
 * COPIED_ASSETS case: staged files persist (nothing is auto-deleted) and make
 * NEGATIVE_CONTROL refuse afterwards.
 *
 * Result `state` values: STARTED, PREPARED, BEFORE_START_LOOP (all
 * non-final - a file stuck in one of them is an interrupted case, never a
 * finished one), COMPLETED (a verdict is present) and HARNESS_ERROR (an
 * unexpected harness failure; the case did NOT complete and the cause is in
 * `harnessError`). A verdict is written only together with COMPLETED or
 * HARNESS_ERROR.
 *
 * What this experiment does NOT test: the wrapper's `mobasset` fallback. By
 * static analysis of the pinned sources it is unreachable (`os.Stat` error is
 * returned by Xray-core before the wrapper's file reader runs); that is a
 * static conclusion, not a runtime result. Success in NEGATIVE_CONTROL is
 * never evidence of `mobasset`. See [GeoExperimentSpec] for exactly what each
 * piece of evidence (SHA-256 of the copy, each case) does and does not show.
 *
 * Supporting metrics only: `TrafficStats` deltas (lag the kernel, skip
 * loopback, cover the whole UID) and RSS/HWM (process-wide, noisy) are
 * recorded for context. Neither proves absence of traffic or that a database
 * was loaded, and neither feeds a verdict.
 *
 * What it NEVER does: establish a VPN or a TUN (`startLoop` gets tunFd 0 and
 * the config has no inbound), open a socket or HTTP connection (no network
 * API of any kind is used - the only network-adjacent calls are the
 * read-only [ConnectivityManager] capability query and the app's own
 * [TrafficStats] byte counters), read or write a profile, credential or
 * server address, use a `freedom`/direct outbound, or delete any file.
 *
 * One case per process: if this process already ran a case the harness
 * refuses - force-stop the app (`am force-stop`, NEVER `pm clear`) between
 * cases. The process is deliberately NOT killed by the harness: it may share
 * `:xray` with a live production session, which the VPN-active precondition
 * rules out but the harness must not be the thing that proves it wrong. A
 * fresh [LibXrayCoreRuntime] says nothing about other cores in the process.
 */
class GeoDbExperimentActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val case = GeoCase.parse(intent?.getStringExtra(EXTRA_CASE))
        val mode = Mode.parse(intent?.getStringExtra(EXTRA_MODE))
        if (savedInstanceState != null || case == null || mode == null) {
            val reason = when {
                case == null -> "unknown-or-missing-case"
                mode == null -> "unknown-or-missing-mode"
                else -> "recreated"
            }
            Log.w(TAG, "GEOEXP|refused|reason=$reason")
            finishAndRemoveTask()
            return
        }
        val codeOverride = GeoExperimentSpec.sanitizeCode(intent.getStringExtra(EXTRA_CODE))
        val appContext = applicationContext
        Thread({
            try {
                runCase(appContext, case, mode, codeOverride)
            } catch (t: Throwable) {
                // Last resort only: failures before a result file exists (no file to write to).
                Log.e(TAG, "GEOEXP|case=${case.id}|mode=${mode.name}|fatal-before-result-file=${oneLine(t.toString())}")
            } finally {
                runOnUiThread { finishAndRemoveTask() }
            }
        }, "geoexp-${case.id}").start()
    }

    /** Mutable progress marker so an unexpected exception can name the step that failed. */
    private class Phase(@Volatile var name: String = "INIT")

    private fun runCase(context: Context, case: GeoCase, mode: Mode, codeOverride: String?) {
        val resultDir = File(context.noBackupFilesDir, "geoexp").apply { mkdirs() }
        val startedAt = System.currentTimeMillis()
        val results = ResultFile.create(resultDir, case, mode, startedAt)
        val out = JSONObject()
            .put("schema", 3)
            .put("state", "STARTED")
            .put("case", case.id)
            .put("mode", mode.name)
            .put("startedAtEpochMs", startedAt)
            .put("sdk", Build.VERSION.SDK_INT)
            .put("pid", Process.myPid())
            .put("uid", Process.myUid())
            .put("expectation", GeoExperimentSpec.expectation(case, mode))
            .put("mobassetTested", false)
            .put("mobassetNote", "mobasset fallback is not exercised; statically unreachable in the pinned Xray (os.Stat error returned first) - not a runtime result")
            .put("dataUseProven", false)
            .put("supportingMetricsNote", "TrafficStats and RSS/HWM are supporting metrics only; neither proves absence of traffic nor database loading")
        codeOverride?.let { out.put("codeOverride", it) }
        val phase = Phase()
        try {
            phase.name = "APP_INFO"
            out.put("app", appInfo(context))
            phase.name = "STARTED_WRITE"
            results.write(out)
            Log.i(TAG, "GEOEXP|case=${case.id}|mode=${mode.name}|state=STARTED|file=${results.name}")
            execute(context, case, mode, codeOverride, results, out, phase)
        } catch (t: Throwable) {
            recordHarnessError(case, mode, results, out, phase.name, t)
        }
    }

    private fun execute(
        context: Context,
        case: GeoCase,
        mode: Mode,
        codeOverride: String?,
        results: ResultFile,
        out: JSONObject,
        phase: Phase,
    ) {
        phase.name = "PRECONDITIONS"
        val processName = readProcessName()
        out.put("processName", processName)
        val xrayAssetsDir = File(context.noBackupFilesDir, "xray-assets")
        val refusedReason: String?
        var prepError: String? = null
        var harnessError: String? = null
        var startedOk = false
        var runningAfterStart = false
        var runningAfterStop = false
        var stopFailed = false
        var errorMessage: String? = null
        var ran = false

        val needsDatabases = case == GeoCase.E0 || GeoExperimentSpec.needsDatabases(case)

        // ---- blocking safety preconditions ----
        val inXrayProcess = processName.endsWith(":xray")
        val freshProcess = !CASE_ALREADY_RUN.getAndSet(true)
        val vpnActive = isAnyVpnActive(context)
        val assetsBefore = listDir(xrayAssetsDir)
        val databasesAbsent = GeoExperimentSpec.DATABASE_FILES.none { it in assetsBefore }
        val apkAssets = try { context.assets.list("")?.toList().orEmpty() } catch (t: Throwable) { emptyList() }
        val apkHasDatabases = GeoExperimentSpec.DATABASE_FILES.all { it in apkAssets }
        out.put(
            "preconditions",
            JSONObject()
                .put("inXrayProcess", inXrayProcess)
                .put("freshProcess", freshProcess)
                .put("noVpnActive", vpnActive == false)
                .put("vpnQueryResult", vpnActive?.toString() ?: "unknown")
                .put("apkAssetsHaveDatabases", apkHasDatabases)
                .put("xrayAssetsHasNoDatabases", databasesAbsent),
        )
        out.put("xrayAssetsBefore", JSONArray(assetsBefore))
        refusedReason = when {
            !inXrayProcess -> "not running in the :xray process ($processName)"
            !freshProcess -> "this process already ran a case - force-stop the app between cases"
            vpnActive != false -> "a VPN network is active or the query was inconclusive ($vpnActive)"
            needsDatabases && !apkHasDatabases -> "APK assets do not contain both database files"
            needsDatabases && mode == Mode.NEGATIVE_CONTROL && !databasesAbsent ->
                "NEGATIVE_CONTROL requires geoip.dat/geosite.dat to be absent from xray-assets (found: $assetsBefore)"
            else -> null
        }

        // ---- source description + staging (never starts the core) ----
        val runtime = LibXrayCoreRuntime()
        if (refusedReason == null && needsDatabases) {
            phase.name = "STAGING"
            val source = GeoAssetStaging.OpenSource { name -> context.assets.open(name) }
            try {
                val sources = GeoExperimentSpec.DATABASE_FILES.map { GeoAssetStaging.describe(it, source) }
                out.put("apkAssetInfo", infoJson(sources))
                if (mode == Mode.COPIED_ASSETS) {
                    if (case == GeoCase.E0) {
                        // Dry run: report what staging WOULD do; write nothing.
                        val plan = GeoAssetStaging.plan(xrayAssetsDir, sources)
                        out.put("stagingPlan", planJson(plan))
                        prepError = plan.conflict
                    } else {
                        val staged = GeoAssetStaging.apply(context.noBackupFilesDir, xrayAssetsDir, sources, source)
                        out.put(
                            "staging",
                            JSONObject()
                                .put("plan", planJson(staged.plan))
                                .put("copied", infoJson(staged.copied))
                                .put("reused", infoJson(staged.reused))
                                .put("error", staged.error ?: JSONObject.NULL),
                        )
                        prepError = staged.error
                    }
                }
            } catch (t: Throwable) {
                // Staging problems are preparation errors, never Xray results; the cause is kept.
                prepError = "staging threw ${t.javaClass.name}: ${t.message}"
                out.put("prepErrorDetail", errorJson("STAGING", t))
            }
            out.put("xrayAssetsAfterPrep", JSONArray(listDir(xrayAssetsDir)))
        }
        phase.name = "PREPARED_WRITE"
        out.put("state", "PREPARED")
        results.write(out)

        // ---- run ----
        val config = GeoExperimentSpec.config(case, codeOverride)
        if (refusedReason == null && prepError == null && config != null) {
            ran = true
            val uid = Process.myUid()
            // Durable breadcrumb BEFORE any native call: an abnormal process end leaves this state behind.
            phase.name = "BEFORE_START_LOOP_WRITE"
            out.put("state", "BEFORE_START_LOOP")
            results.write(out)
            Log.i(TAG, "GEOEXP|case=${case.id}|mode=${mode.name}|start|file=${results.name}")
            phase.name = "CORE_ENV_INIT"
            val before = snapshot(uid)
            val initStart = SystemClock.elapsedRealtimeNanos()
            try {
                runtime.ensureCoreEnvInitialized(context)
            } catch (t: Throwable) {
                harnessError = "core env init failed (before startLoop - not an Xray start result): ${t.javaClass.name}: ${t.message}"
                out.put("harnessErrorDetail", errorJson("CORE_ENV_INIT", t))
            }
            out.put("initCoreEnvMs", (SystemClock.elapsedRealtimeNanos() - initStart) / 1_000_000.0)
            if (harnessError == null) {
                phase.name = "START_LOOP"
                val afterInit = snapshot(uid)
                val startNanos = SystemClock.elapsedRealtimeNanos()
                try {
                    runtime.startLoop(config, 0)
                    startedOk = true
                } catch (t: Throwable) {
                    // The Xray/wrapper start failure under test. Only its message is judged; the stack is recorded apart.
                    errorMessage = t.message ?: t.toString()
                    out.put("errorType", t.javaClass.name)
                    out.put("errorStack", stackOf(t))
                }
                val startMs = (SystemClock.elapsedRealtimeNanos() - startNanos) / 1_000_000.0
                runningAfterStart = runtime.isRunning
                val afterStart = snapshot(uid)
                phase.name = "STOP_LOOP"
                try {
                    runtime.stopLoop()
                } catch (t: Throwable) {
                    stopFailed = true
                    out.put("stopError", errorJson("STOP_LOOP", t))
                }
                runningAfterStop = runtime.isRunning
                val afterStop = snapshot(uid)
                out.put("startLoopMs", startMs)
                out.put("snapshotBefore", before)
                out.put("snapshotAfterInit", afterInit)
                out.put("snapshotAfterStart", afterStart)
                out.put("snapshotAfterStop", afterStop)
                out.put("uidTxDeltaBytes", delta(before, afterStop, "uidTxBytes"))
                out.put("uidRxDeltaBytes", delta(before, afterStop, "uidRxBytes"))
            }
            out.put("xrayAssetsAfter", JSONArray(listDir(xrayAssetsDir)))
        }

        phase.name = "JUDGEMENT"
        val judgement = GeoExperimentSpec.judge(
            case,
            mode,
            GeoExperimentSpec.Observation(
                refusedReason = refusedReason,
                prepError = prepError,
                harnessError = harnessError,
                startedOk = startedOk,
                runningAfterStart = runningAfterStart,
                runningAfterStop = runningAfterStop,
                stopFailed = stopFailed,
                errorMessage = errorMessage,
            ),
        )
        val finalState = if (judgement.verdict == Verdict.HARNESS_ERROR) "HARNESS_ERROR" else "COMPLETED"
        out.put("ran", ran)
        out.put("startedOk", startedOk)
        out.put("runningAfterStart", runningAfterStart)
        out.put("runningAfterStop", runningAfterStop)
        out.put("stopFailed", stopFailed)
        out.put("errorClass", GeoExperimentSpec.classify(errorMessage).name)
        errorMessage?.let { out.put("error", it) }
        refusedReason?.let { out.put("refusedReason", it) }
        prepError?.let { out.put("prepError", it) }
        harnessError?.let { out.put("harnessError", it) }
        out.put("verdict", judgement.verdict.name)
        out.put("verdictReason", judgement.reason)
        out.put("state", finalState)
        phase.name = "FINAL_WRITE"
        results.write(out)
        Log.i(
            TAG,
            "GEOEXP|case=${case.id}|mode=${mode.name}|state=$finalState|verdict=${judgement.verdict}|ran=$ran" +
                "|errorClass=${out.optString("errorClass")}|startLoopMs=${out.opt("startLoopMs")}" +
                "|rssBeforeKb=${out.optJSONObject("snapshotBefore")?.opt("vmRssKb")}" +
                "|rssAfterStartKb=${out.optJSONObject("snapshotAfterStart")?.opt("vmRssKb")}" +
                "|uidTxDelta=${out.opt("uidTxDeltaBytes")}|uidRxDelta=${out.opt("uidRxDeltaBytes")}|file=${results.name}",
        )
        Log.i(TAG, "GEOEXP|case=${case.id}|mode=${mode.name}|reason=${oneLine(judgement.reason)}")
        out.optString("error").takeIf { it.isNotEmpty() }?.let { Log.i(TAG, "GEOEXP|case=${case.id}|mode=${mode.name}|error=${oneLine(it)}") }
    }

    /**
     * An unexpected exception anywhere in the harness (not a staging problem and not the
     * startLoop failure under test, both of which are handled in place). Never writes COMPLETED
     * or a PASS: the state becomes HARNESS_ERROR with the original cause. If the result file
     * cannot be written either, both failures are logged.
     */
    private fun recordHarnessError(case: GeoCase, mode: Mode, results: ResultFile, out: JSONObject, phase: String, cause: Throwable) {
        Log.e(
            TAG,
            "GEOEXP|case=${case.id}|mode=${mode.name}|state=HARNESS_ERROR|phase=$phase|type=${cause.javaClass.name}|message=${oneLine(cause.message ?: "")}",
        )
        try {
            out.put("harnessError", "unexpected harness error in phase $phase: ${cause.javaClass.name}: ${cause.message}")
            out.put("harnessErrorDetail", errorJson(phase, cause))
            out.put("verdict", Verdict.HARNESS_ERROR.name)
            out.put("verdictReason", "unexpected harness error in phase $phase; the case did not complete")
            out.put("state", "HARNESS_ERROR")
            results.write(out)
        } catch (writeFailure: Throwable) {
            Log.e(
                TAG,
                "GEOEXP|case=${case.id}|mode=${mode.name}|result-write-failed|writeError=${oneLine(writeFailure.toString())}" +
                    "|originalPhase=$phase|originalError=${oneLine(cause.toString())}",
            )
        }
    }

    /**
     * One result file per run, created with create-new semantics (an earlier
     * result is never overwritten) and rewritten atomically as the run
     * progresses, so an interrupted run stays findable by its last `state`.
     * Rewrites go through a fresh temp file that is renamed over the run's own
     * result file; nothing is deleted.
     */
    private class ResultFile private constructor(private val file: File) {
        val name: String get() = file.name

        fun write(json: JSONObject) {
            val tmp = File(file.parentFile, file.name + ".tmp")
            if (!tmp.createNewFile()) throw java.io.IOException("result temp file exists: ${tmp.name}")
            FileOutputStream(tmp).use { out ->
                out.write(json.toString(2).toByteArray(Charsets.UTF_8))
                out.flush()
                out.fd.sync()
            }
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        }

        companion object {
            fun create(dir: File, case: GeoCase, mode: Mode, ts: Long): ResultFile {
                var n = 0
                while (true) {
                    val f = File(dir, "geoexp-${case.id}-${mode.name}-$ts${if (n == 0) "" else "-$n"}.json")
                    if (f.createNewFile()) return ResultFile(f)
                    n++
                }
            }
        }
    }

    private fun appInfo(context: Context): JSONObject {
        val out = JSONObject().put("package", context.packageName)
        try {
            @Suppress("DEPRECATION")
            val pi = context.packageManager.getPackageInfo(context.packageName, 0)
            @Suppress("DEPRECATION")
            val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) pi.longVersionCode else pi.versionCode.toLong()
            out.put("versionName", pi.versionName ?: JSONObject.NULL).put("versionCode", code).put("lastUpdateTime", pi.lastUpdateTime)
        } catch (t: Throwable) {
            out.put("error", t.javaClass.simpleName)
        }
        return out
    }

    private fun infoJson(files: List<GeoAssetStaging.FileInfo>): JSONObject {
        val o = JSONObject()
        files.forEach { o.put(it.name, JSONObject().put("size", it.size).put("sha256", it.sha256)) }
        return o
    }

    private fun planJson(plan: GeoAssetStaging.Plan): JSONObject {
        val actions = JSONObject()
        plan.actions.forEach { (name, action) -> actions.put(name, action.name) }
        return JSONObject().put("actions", actions).put("conflict", plan.conflict ?: JSONObject.NULL)
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

    private fun stackOf(t: Throwable): String = Log.getStackTraceString(t).lineSequence().take(40).joinToString("\n")

    /** Structured record of an exception: the original type/message, up to five causes, and a trimmed stack. */
    private fun errorJson(phase: String, t: Throwable): JSONObject {
        val causes = JSONArray()
        var cause = t.cause
        var depth = 0
        while (cause != null && depth < 5) {
            causes.put(JSONObject().put("type", cause.javaClass.name).put("message", cause.message ?: JSONObject.NULL))
            cause = cause.cause
            depth++
        }
        return JSONObject()
            .put("phase", phase)
            .put("type", t.javaClass.name)
            .put("message", t.message ?: JSONObject.NULL)
            .put("causes", causes)
            .put("stack", stackOf(t))
    }

    private fun oneLine(s: String): String = s.replace("\r", "").replace("\n", "\\n").take(2000)

    companion object {
        private const val TAG = "GeoExp"
        const val EXTRA_CASE = "case"
        const val EXTRA_MODE = "mode"
        const val EXTRA_CODE = "code"

        /** Process-wide: a second case in the same process is refused (see class docs). */
        private val CASE_ALREADY_RUN = AtomicBoolean(false)
    }
}
