package net.pocvpn.client.debug.geort

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import net.pocvpn.client.vpn.xray.GeoDataBootstrap
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import net.pocvpn.client.vpn.xray.asGeoAssetSource
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * GEO-RUNTIME-EXPERIMENT E0-E6 - TEST ONLY (debug source set, never committed). One case per process:
 *   --es case E0 | E1 | RUN | E5_INIT | E5_SCRATCH | TUN
 *   RUN needs --es rule geoip|geosite|geoip_unknown|geosite_unknown|root_control
 *   E5_INIT / E5_SCRATCH take --ei n <reps>
 *   TUN needs --es scenario OK|FAIL --ei probes 0|1 (asks for the VPN consent once)
 * Force-stop the package between cases (never `pm clear`). Results: the .json files in noBackupFilesDir/geort and GeoRt logcat lines.
 */
class GeoRuntimeExperimentActivity : Activity() {

    private var tunExtras: Intent? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val case = intent?.getStringExtra("case")
        if (savedInstanceState != null || case == null || !CASE_RAN.compareAndSet(false, true)) {
            Log.w(GeoRt.TAG, "GEORT|refused|case=$case")
            finishAndRemoveTask()
            return
        }
        if (case == "TUN") {
            val prep = VpnService.prepare(this)
            if (prep != null) {
                Log.i(GeoRt.TAG, "GEORT|vpn-consent-needed")
                @Suppress("DEPRECATION")
                startActivityForResult(prep, 77)
                return
            }
            startTun()
            return
        }
        val ctx = applicationContext
        val intentCopy = intent
        Thread({
            try {
                val out = JSONObject().put("case", case).put("device", GeoRt.deviceInfo()).put("process", GeoRt.processName())
                when (case) {
                    "E0" -> e0(ctx, out)
                    "E1" -> e1(ctx, out)
                    "RUN" -> run(ctx, out, intentCopy.getStringExtra("rule") ?: "")
                    "E5_INIT" -> e5Init(ctx, out, intentCopy.getIntExtra("n", 7))
                    "E5_SCRATCH" -> e5Scratch(ctx, out, intentCopy.getIntExtra("n", 7))
                    else -> out.put("error", "unknown case")
                }
                GeoRt.writeResult(ctx, "$case-${intentCopy.getStringExtra("rule") ?: ""}-${System.currentTimeMillis()}", out)
            } catch (t: Throwable) {
                Log.e(GeoRt.TAG, "GEORT|case=$case|harness-error=${t.javaClass.name}: ${t.message}")
            } finally {
                runOnUiThread { finishAndRemoveTask() }
            }
        }, "geort-$case").start()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == 77 && resultCode == RESULT_OK) {
            startTun()
        } else {
            Log.w(GeoRt.TAG, "GEORT|vpn-consent-declined|resultCode=$resultCode")
            finishAndRemoveTask()
        }
    }

    private fun startTun() {
        val svc = Intent(this, GeoRuntimeVpnService::class.java)
            .putExtra("scenario", intent.getStringExtra("scenario") ?: "OK")
            .putExtra("probes", intent.getIntExtra("probes", 0))
            .putExtra("order", intent.getStringExtra("order") ?: "TUN_FIRST")
        startService(svc)
        finishAndRemoveTask()
    }

    // ---- E0: baseline, writes/starts nothing ------------------------------------------------
    private fun e0(ctx: Context, out: JSONObject) {
        val pm = ctx.packageManager
        @Suppress("DEPRECATION")
        val pi = pm.getPackageInfo(ctx.packageName, 0)
        out.put("package", ctx.packageName).put("versionName", pi.versionName).put("lastUpdateTime", pi.lastUpdateTime)
        out.put("debuggable", (ctx.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        val nativeDir = File(ctx.applicationInfo.nativeLibraryDir)
        val libs = JSONArray()
        nativeDir.listFiles()?.sortedBy { it.name }?.forEach {
            libs.put(JSONObject().put("name", it.name).put("size", it.length()).put("sha256", if (it.name == "libgojni.so") GeoRt.sha256(it) else JSONObject.NULL))
        }
        out.put("nativeLibraryDir", nativeDir.path).put("nativeLibs", libs)
        out.put("xrayVersion", try { libv2ray.Libv2ray.checkVersionX() } catch (t: Throwable) { "unavailable:${t.javaClass.simpleName}" })
        val assets = JSONObject()
        listOf("geoip.dat", "geosite.dat").forEach { n ->
            val (size, sha) = GeoRt.sha256Asset(ctx, n)
            assets.put(n, JSONObject().put("size", size).put("sha256", sha))
        }
        out.put("apkAssetGeo", assets)
        out.put("noBackupDir", GeoRt.listDir(ctx.noBackupFilesDir))
        out.put("xrayAssetsDir", GeoRt.listDir(File(ctx.noBackupFilesDir, "xray-assets")))
        out.put("databasesDir", GeoRt.listDir(File(ctx.applicationInfo.dataDir, "databases")))
    }

    // ---- E1: production publish path ----------------------------------------------------------
    private fun e1(ctx: Context, out: JSONObject) {
        val t0 = SystemClock.elapsedRealtimeNanos()
        LibXrayCoreRuntime().ensureCoreEnvInitialized(ctx)
        val t1 = SystemClock.elapsedRealtimeNanos()
        out.put("ensureCoreEnvInitializedMs", GeoRt.ms(t0, t1))
        val root = File(ctx.noBackupFilesDir, "xray-assets")
        out.put("xrayAssetsListing", GeoRt.listDir(root))
        val datasets = JSONArray()
        root.listFiles()?.filter { it.isDirectory && it.name.startsWith("geo-") && !it.name.contains(".quarantine-") }?.forEach { d ->
            val files = JSONObject()
            d.listFiles()?.sortedBy { it.name }?.forEach { f ->
                files.put(f.name, JSONObject().put("size", f.length()).put("sha256", GeoRt.sha256(f)))
            }
            val marker = File(d, ".geo-dataset.json")
            datasets.put(
                JSONObject().put("dir", d.name).put("files", files)
                    .put("marker", if (marker.isFile) JSONObject(marker.readText()) else JSONObject.NULL),
            )
        }
        out.put("datasets", datasets)
    }

    // ---- E2/E3/E4: production runtime, real routing evaluation over loopback -----------------
    private fun run(ctx: Context, out: JSONObject, rule: String) {
        val (ruleText, probes) = when (rule) {
            "geoip" -> "geoip:ru" to listOf(GeoRt.IP_HIT, GeoRt.IP_MISS)
            "geosite" -> "geosite:yandex" to listOf(GeoRt.DOMAIN_HIT, GeoRt.DOMAIN_MISS)
            "geoip_unknown" -> "geoip:${GeoRt.UNKNOWN_CODE}" to emptyList()
            "geosite_unknown" -> "geosite:${GeoRt.UNKNOWN_CODE}" to emptyList()
            "root_control" -> "geoip:ru" to emptyList()
            else -> { out.put("error", "unknown rule"); return }
        }
        out.put("rule", ruleText)
        val root = File(ctx.noBackupFilesDir, "xray-assets")
        out.put("xrayAssetsBefore", GeoRt.listDir(root))
        val runtime = LibXrayCoreRuntime()
        val tInit0 = SystemClock.elapsedRealtimeNanos()
        if (rule == "root_control") {
            // NOT the production path: points initCoreEnv at the plain xray-assets root (no flat db files there).
            go.Seq.setContext(ctx)
            libv2ray.Libv2ray.initCoreEnv(root.absolutePath, "")
            out.put("assetPathGiven", root.absolutePath)
        } else {
            runtime.ensureCoreEnvInitialized(ctx)
        }
        out.put("initMs", GeoRt.ms(tInit0, SystemClock.elapsedRealtimeNanos()))
        val cfg = GeoRt.config(ruleText, withSocks = true, withTun = false)
        var started = false
        try {
            val t0 = SystemClock.elapsedRealtimeNanos()
            runtime.startLoop(cfg, 0)
            started = true
            out.put("startLoopMs", GeoRt.ms(t0, SystemClock.elapsedRealtimeNanos()))
            val results = JSONArray()
            probes.forEach { results.put(GeoRt.socksProbe(it)) }
            out.put("probes", results)
        } catch (t: Throwable) {
            out.put("startError", t.message ?: t.toString()).put("startErrorType", t.javaClass.name)
        }
        out.put("started", started)
        try { runtime.stopLoop() } catch (t: Throwable) { out.put("stopError", t.toString()) }
        out.put("runningAfterStop", runtime.isRunning)
        out.put("xrayAssetsAfter", GeoRt.listDir(root))
        Log.i(GeoRt.TAG, "GEORT|case=RUN|rule=$rule|started=$started|probes=${out.opt("probes")}|error=${out.opt("startError")}")
    }

    // ---- E5: production ensureCoreEnvInitialized timing, same process, kept dataset ----------
    private fun e5Init(ctx: Context, out: JSONObject, n: Int) {
        val reps = JSONArray()
        repeat(n) {
            val rt = LibXrayCoreRuntime()
            val t0 = SystemClock.elapsedRealtimeNanos()
            rt.ensureCoreEnvInitialized(ctx)
            reps.put(GeoRt.ms(t0, SystemClock.elapsedRealtimeNanos()))
        }
        out.put("ensureMsPerRep", reps)
    }

    // ---- E5: first publish, repeated on fresh scratch roots (never touches xray-assets) -------
    private fun e5Scratch(ctx: Context, out: JSONObject, n: Int) {
        val first = JSONArray(); val second = JSONArray(); val outcomes = JSONArray()
        val base = File(ctx.noBackupFilesDir, "geort-scratch").apply { mkdirs() }
        val stamp = System.currentTimeMillis()
        repeat(n) { i ->
            val root = File(base, "r$stamp-$i")
            val logs = ArrayList<String>()
            val t0 = SystemClock.elapsedRealtimeNanos()
            GeoDataBootstrap.resolveAssetDirectory(root, ctx.assets.asGeoAssetSource()) { logs.add(it) }
            val t1 = SystemClock.elapsedRealtimeNanos()
            GeoDataBootstrap.resolveAssetDirectory(root, ctx.assets.asGeoAssetSource()) { logs.add(it) }
            val t2 = SystemClock.elapsedRealtimeNanos()
            first.put(GeoRt.ms(t0, t1)); second.put(GeoRt.ms(t1, t2))
            outcomes.put(JSONArray(logs.map { it.substringBefore(" id=") }))
        }
        out.put("firstPublishMs", first).put("existingDatasetMs", second).put("outcomes", outcomes)
    }

    companion object {
        private val CASE_RAN = AtomicBoolean(false)
    }
}
