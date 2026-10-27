package net.pocvpn.client.debug.geort

import android.annotation.SuppressLint
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * GEO-RUNTIME-EXPERIMENT E5/E6 - TEST ONLY (debug source set, never committed).
 *
 * Reproduces the ORDER of XrayCoreController.requestStart (establishTun -> ensureCoreEnvInitialized
 * -> startLoop, see XrayCoreController.kt "establishTun(plan)") with the production
 * [LibXrayCoreRuntime], a fixed blackhole-only config and NO production profile. It is not
 * NovaXrayVpnService and does not exercise XrayCoreController itself.
 *
 * Safety: the TUN is established with addAllowedApplication(own package) ONLY, so no other app's
 * traffic is captured. With probes=1 a plain HTTP GET to 1.1.1.1:80 is attempted every 100 ms from
 * this app: a real HTTP status line means the packet left the tunnel (a leak).
 */
class GeoRuntimeVpnService : VpnService() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!STARTED.compareAndSet(false, true)) return START_NOT_STICKY
        val scenario = intent?.getStringExtra("scenario") ?: "OK"
        val probes = intent?.getIntExtra("probes", 0) ?: 0
        val order = intent?.getStringExtra("order") ?: "TUN_FIRST"
        Thread({ runScenario(scenario, probes, order) }, "geort-tun").start()
        return START_NOT_STICKY
    }

    @SuppressLint("VpnServicePolicy")
    private fun runScenario(scenario: String, probes: Int, order: String) {
        val out = JSONObject().put("case", "TUN").put("scenario", scenario).put("probes", probes).put("order", order)
            .put("runId", "$order-$scenario-p$probes-${System.currentTimeMillis()}")
            .put("device", GeoRt.deviceInfo()).put("process", GeoRt.processName())
        val marks = JSONObject()
        val probeResults = java.util.Collections.synchronizedList(ArrayList<JSONObject>())
        val runtime = LibXrayCoreRuntime()
        var pfd: ParcelFileDescriptor? = null
        try {
            if (probes == 1) out.put("controlProbeBeforeTun", GeoRt.leakProbe(2500, applicationContext))
            marks.put("serviceStartNs", SystemClock.elapsedRealtimeNanos())
            val b = Builder().setSession("geort").setMtu(1500).addAddress("172.19.0.1", 30).addRoute("0.0.0.0", 0)
            b.addAllowedApplication(packageName)
            // order=ENSURE_FIRST (comparison variant): ensureCoreEnvInitialized BEFORE establish().
            // Default TUN_FIRST is the unchanged control (establish -> ensure -> startLoop).
            if (order == "ENSURE_FIRST") {
                marks.put("ensureBeginNs", SystemClock.elapsedRealtimeNanos())
                runtime.ensureCoreEnvInitialized(applicationContext)
                marks.put("ensureEndNs", SystemClock.elapsedRealtimeNanos())
            }
            marks.put("establishCallNs", SystemClock.elapsedRealtimeNanos())
            pfd = b.establish()
            marks.put("tunEstablishedNs", SystemClock.elapsedRealtimeNanos())
            if (pfd == null) {
                out.put("error", "establish() returned null")
            } else {
                if (probes == 1) {
                    Thread({
                        repeat(40) { i ->
                            Thread({ probeResults.add(GeoRt.leakProbe(1500, applicationContext).put("index", i)) }, "geort-probe-$i").apply { isDaemon = true }.start()
                            Thread.sleep(100)
                        }
                    }, "geort-probe-launcher").apply { isDaemon = true }.start()
                }
                if (order != "ENSURE_FIRST") {
                    marks.put("ensureBeginNs", SystemClock.elapsedRealtimeNanos())
                    runtime.ensureCoreEnvInitialized(applicationContext)
                    marks.put("ensureEndNs", SystemClock.elapsedRealtimeNanos())
                }
                val rule = if (scenario == "FAIL") "geoip:${GeoRt.UNKNOWN_CODE}" else "geoip:ru"
                val cfg = GeoRt.config(rule, withSocks = false, withTun = true)
                var started = false
                try {
                    marks.put("startLoopBeginNs", SystemClock.elapsedRealtimeNanos())
                    runtime.startLoop(cfg, pfd.fd)
                    marks.put("startLoopEndNs", SystemClock.elapsedRealtimeNanos())
                    started = true
                } catch (t: Throwable) {
                    marks.put("startLoopFailedNs", SystemClock.elapsedRealtimeNanos())
                    out.put("startError", t.message ?: t.toString())
                    // Same as production CoreStartFailed path: the just-established tun is closed.
                    try { pfd.close() } catch (_: Throwable) {}
                    marks.put("tunClosedNs", SystemClock.elapsedRealtimeNanos())
                    pfd = null
                }
                out.put("started", started)
                if (started) {
                    Thread.sleep(4500)
                    try { runtime.stopLoop() } catch (t: Throwable) { out.put("stopError", t.toString()) }
                    try { pfd.close() } catch (_: Throwable) {}
                    marks.put("tunClosedNs", SystemClock.elapsedRealtimeNanos())
                    pfd = null
                } else {
                    Thread.sleep(2500)
                }
            }
        } catch (t: Throwable) {
            out.put("error", "${t.javaClass.name}: ${t.message}")
        } finally {
            try { pfd?.close() } catch (_: Throwable) {}
        }
        if (probes == 1) {
            Thread.sleep(1800)
            out.put("probeAfterTunClosed", GeoRt.leakProbe(2500, applicationContext))
        }
        // Derived durations (monotonic clock, elapsedRealtimeNanos).
        fun d(a: String, b: String): Any = if (marks.has(a) && marks.has(b)) GeoRt.ms(marks.getLong(a), marks.getLong(b)) else JSONObject.NULL
        out.put("marksNs", marks)
        out.put("tunToEnsureBeginMs", d("tunEstablishedNs", "ensureBeginNs"))
        out.put("ensureMs", d("ensureBeginNs", "ensureEndNs"))
        out.put("tunToStartLoopBeginMs", d("tunEstablishedNs", "startLoopBeginNs"))
        out.put("startLoopMs", d("startLoopBeginNs", "startLoopEndNs"))
        val tun = if (marks.has("tunEstablishedNs")) marks.getLong("tunEstablishedNs") else 0L
        val rows = JSONArray()
        synchronized(probeResults) {
            probeResults.sortedBy { it.optInt("index") }.forEach { p ->
                val s = p.optLong("startNs"); val e = p.optLong("endNs")
                rows.put(
                    JSONObject().put("index", p.optInt("index")).put("outcome", p.optString("outcome"))
                        .put("startAfterTunMs", GeoRt.ms(tun, s)).put("durationMs", GeoRt.ms(s, e))
                        .put("startNs", s).put("endNs", e)
                        .put("connectedNs", if (p.has("connectedNs")) p.getLong("connectedNs") else JSONObject.NULL)
                        .put("firstDataNs", if (p.has("firstDataNs")) p.getLong("firstDataNs") else JSONObject.NULL)
                        .put("firstLine", p.optString("firstLine"))
                        .put("diag", p.opt("diag") ?: JSONObject.NULL),
                )
            }
        }
        out.put("probeRows", rows)
        val leaks = (0 until rows.length()).count { rows.getJSONObject(it).getString("outcome") == "REAL_RESPONSE" }
        out.put("realResponses", leaks)
        GeoRt.writeResult(applicationContext, "TUN-$order-$scenario-p$probes-${System.currentTimeMillis()}", out)
        Log.i(
            GeoRt.TAG,
            "GEORT|case=TUN|scenario=$scenario|started=${out.opt("started")}|ensureMs=${out.opt("ensureMs")}" +
                "|tunToStartLoopBeginMs=${out.opt("tunToStartLoopBeginMs")}|startLoopMs=${out.opt("startLoopMs")}|realResponses=$leaks",
        )
        stopSelf()
    }

    companion object {
        private val STARTED = AtomicBoolean(false)
    }
}
