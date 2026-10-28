package net.pocvpn.client.debug.f2

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import net.pocvpn.client.vpn.VlessXhttpTransport

/**
 * F2A - DEBUG-ONLY experiment harness (not a feature). Runs ONE bounded attempt through the
 * real [VlessXhttpTransport] -> NovaXrayVpnService -> pinned Xray splithttp dialer with a
 * test-only XHTTP config built by [F2XhttpTestProfile]. See that object for what is refused.
 *
 * Absent from release: it lives in the `debug` source set and is declared only in
 * src/debug/AndroidManifest.xml (protected by android.permission.DUMP, shell-launchable only).
 * It writes nothing to any profile/activation store: the config lives only in the process-local
 * XhttpSessionConfigStore for the one session, under the dedicated endpoint id
 * [F2XhttpTestProfile.ENDPOINT_ID].
 *
 * Launch (extras are the ONLY inputs; nothing is read from storage):
 *   am start -n net.pocvpn.client/net.pocvpn.client.debug.f2.F2XhttpHarnessActivity
 *     --es dialHost <IPv4 private/loopback | *.invalid|*.test|*.example|*.localhost>
 *     --ei port <n> --es sni <reserved test hostname> [--es httpHost <reserved test hostname>]
 *     [--es path /x/] [--es alpn h2|http/1.1] [--es mode packet-up|stream-up|stream-one|auto]
 *     [--ei maxSeconds 5..60]
 * Stop early: --es op stop (or the Stop button). Results are in logcat, tag [TAG].
 */
class F2XhttpHarnessActivity : AppCompatActivity() {

    private lateinit var status: TextView
    private var pendingStart: F2XhttpTestProfile.BuildResult.Ok? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        status = TextView(this).apply { text = "F2A XHTTP harness (debug). Waiting for intent extras." }
        root.addView(status)
        root.addView(Button(this).apply {
            text = "Stop F2 harness run"
            setOnClickListener { stopRun() }
        })
        setContentView(root)
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent) {
        if (intent.getStringExtra("op") == "stop") {
            stopRun()
            return
        }
        if (!intent.hasExtra("dialHost")) return // plain launch: do nothing
        val built = F2XhttpTestProfile.build(
            dialHost = intent.getStringExtra("dialHost"),
            port = intent.takeIf { it.hasExtra("port") }?.getIntExtra("port", -1),
            sni = intent.getStringExtra("sni"),
            httpHost = intent.getStringExtra("httpHost"),
            path = intent.getStringExtra("path"),
            alpn = intent.getStringExtra("alpn"),
            mode = intent.getStringExtra("mode"),
            maxSeconds = intent.takeIf { it.hasExtra("maxSeconds") }?.getIntExtra("maxSeconds", -1),
        )
        when (built) {
            is F2XhttpTestProfile.BuildResult.Rejected -> {
                status.text = "Refused: ${built.reason}"
                Log.w(TAG, "refused: ${built.reason}")
            }
            is F2XhttpTestProfile.BuildResult.Ok -> {
                if (activeJob?.isActive == true) {
                    status.text = "A run is already active; stop it first."
                    return
                }
                val consent = VpnService.prepare(this)
                if (consent != null) {
                    pendingStart = built
                    @Suppress("DEPRECATION")
                    startActivityForResult(consent, REQUEST_VPN_CONSENT)
                } else {
                    start(built)
                }
            }
        }
    }

    @Deprecated("Debug harness only")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_VPN_CONSENT) return
        val pending = pendingStart
        pendingStart = null
        if (resultCode == RESULT_OK && pending != null) start(pending) else status.text = "VPN consent not granted."
    }

    private fun start(built: F2XhttpTestProfile.BuildResult.Ok) {
        val transport = VlessXhttpTransport(applicationContext)
        val runner = F2XhttpRunner(transport)
        // config.toString() redacts the UUID; it carries only the test dial/SNI/Host values.
        Log.i(TAG, "start maxMs=${built.maxMillis} ${built.transportConfig.config}")
        status.text = "Run started (max ${built.maxMillis / 1000}s). See logcat tag $TAG."
        activeJob = harnessScope.launch {
            val outcome = runner.run(built.transportConfig, built.maxMillis) { e ->
                Log.i(TAG, "+${e.elapsedMs}ms state=${e.state}")
            }
            Log.i(TAG, "outcome=$outcome")
        }
    }

    private fun stopRun() {
        // Cancelling the job runs the runner's finally: transport.disconnect() for THIS run's session only.
        activeJob?.cancel()
        status.text = "Stop requested."
        Log.i(TAG, "stop requested")
    }

    companion object {
        const val TAG = "F2XhttpHarness"
        private const val REQUEST_VPN_CONSENT = 0xF2

        // Process-local (main process) so a run survives activity recreation and a second
        // intent can stop it.
        private val harnessScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        @Volatile private var activeJob: Job? = null
    }
}
