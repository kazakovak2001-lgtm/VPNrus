package net.pocvpn.client.debug.b45a

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val VPN_PERMISSION_REQUEST_CODE = 4501
private const val TAG = "B45AExecProbe"

/**
 * B45A - SPIKE ONLY, NOT PRODUCTION CONNECTION AUTHORITY.
 *
 * Debug-build-only manual entry point for [B45ASpikeVpnService], mirroring
 * [net.pocvpn.client.debug.XrayDiagnosticsActivity]'s own isolation
 * discipline (B8K1B) - present only via the `debug` Gradle source set's own
 * `AndroidManifest.xml` fragment, genuinely absent from a release APK.
 *
 * Shows exactly the status lines Phase 11 asked for. Never displays the
 * spike's fake test credential or raw upstream stderr (that stays in
 * app-private debug log output only, via [android.util.Log], never surfaced
 * here) - see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's own security-boundary
 * section.
 */
class B45ASpikeActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var udpResultText: TextView
    private var currentStatus: B45ASpikeStatus = B45ASpikeStatus.IDLE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }

        statusText = TextView(this).apply { text = "B45A spike - not started" }
        root.addView(statusText)

        val startButton = Button(this).apply {
            text = "B45A Start"
            setOnClickListener { requestVpnPermissionThenStart() }
        }
        root.addView(startButton)

        val stopButton = Button(this).apply {
            text = "B45A Stop"
            setOnClickListener {
                startService(Intent(this@B45ASpikeActivity, B45ASpikeVpnService::class.java).setAction(B45ASpikeVpnService.ACTION_STOP))
            }
        }
        root.addView(stopButton)

        // B45A packaging-route Phase 5 execution probe (temporary,
        // ungated by ACTION_START/B45ARuntime): a standalone, zero-network
        // ProcessBuilder invocation of the nativeLibraryDir-extracted
        // binary with `--version` only - never touches VpnService.Builder,
        // B45ARuntime, TUN, or the protect bridge, so it cannot reach the
        // TUN-fd handoff phase even indirectly. Exists solely to prove
        // whether the real app process can exec() the packaging-fixed
        // binary; see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's packaging-route
        // investigation section.
        val execProbeButton = Button(this).apply {
            text = "B45A Exec Probe (--version, no VPN)"
            setOnClickListener { runExecProbe() }
        }
        root.addView(execProbeButton)

        // B45A final UDP round-trip proof (Section 30's own "controlled UDP
        // echo" requirement): 3 independent nonce round trips against the
        // temporary Frankfurt echo endpoint (B45AUdpEchoProbe). Gated on
        // RUNNING so it can only ever exercise the real, currently-active
        // TUN - never a stale or absent tunnel silently "passing" because
        // the probe ran with B45A stopped.
        val udpProbeButton = Button(this).apply {
            text = "B45A UDP Echo x3"
            setOnClickListener { runUdpEchoProbe() }
        }
        root.addView(udpProbeButton)

        udpResultText = TextView(this).apply { text = "udp probe: not run" }
        root.addView(udpResultText)

        setContentView(root)

        lifecycleScope.launch {
            B45ASpikeVpnService.status.collect { status ->
                currentStatus = status
                statusText.text = renderStatus(status)
            }
        }
    }

    private fun runUdpEchoProbe() {
        if (currentStatus.phase != B45ARuntimePhase.RUNNING) {
            udpResultText.text = "udp probe: REFUSED - B45A is not RUNNING (phase=${currentStatus.phase})"
            return
        }
        udpResultText.text = "udp probe: running 3 round trips ..."
        lifecycleScope.launch {
            val results = withContext(Dispatchers.IO) {
                (1..3).map { B45AUdpEchoProbe.roundTrip() }
            }
            udpResultText.text = buildString {
                results.forEachIndexed { index, r ->
                    appendLine(
                        "#${index + 1} nonce=${r.nonce} matched=${r.matched} latency=${r.latencyMillis}ms" +
                            (r.error?.let { " error=$it" } ?: ""),
                    )
                }
                val allMatched = results.all { it.matched }
                appendLine("overall: ${if (allMatched) "PASS (3/3 exact matches)" else "FAIL"}")
            }
            Log.i(TAG, "udp echo probe results: $results")
        }
    }

    private fun requestVpnPermissionThenStart() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityForResult(prepareIntent, VPN_PERMISSION_REQUEST_CODE)
        } else {
            startService(Intent(this, B45ASpikeVpnService::class.java).setAction(B45ASpikeVpnService.ACTION_START))
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION_REQUEST_CODE && resultCode == RESULT_OK) {
            startService(Intent(this, B45ASpikeVpnService::class.java).setAction(B45ASpikeVpnService.ACTION_START))
        }
    }

    private fun runExecProbe() {
        // Same B45ANativeBinaryResolver call the real B45ASpikeVpnService
        // start flow uses (Section 26.7's "exec probe path == real runtime
        // path" invariant) - no separate, potentially-diverging path logic.
        val resolution = B45ANativeBinaryResolver.resolve(applicationInfo.nativeLibraryDir)
        statusText.text = "exec probe: resolving binary ..."
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                try {
                    val binary = when (resolution) {
                        is B45ANativeBinaryResolver.Result.Missing -> return@withContext "FAIL: ${resolution.reason}"
                        is B45ANativeBinaryResolver.Result.Found -> resolution.file
                    }
                    val process = ProcessBuilder(binary.absolutePath, "--version")
                        .redirectErrorStream(true)
                        .start()
                    val output = process.inputStream.bufferedReader().readText().trim()
                    val exitCode = process.waitFor()
                    "exit=$exitCode output=\"$output\""
                } catch (e: Exception) {
                    Log.e(TAG, "exec probe failed", e)
                    "FAIL: ${e.javaClass.simpleName}: ${e.message}"
                }
            }
            Log.i(TAG, "exec probe result: $result")
            statusText.text = "exec probe result:\n$result"
        }
    }

    private fun renderStatus(status: B45ASpikeStatus): String = buildString {
        appendLine("SPIKE ONLY - not a production transport")
        appendLine("phase: ${status.phase}")
        appendLine("pid: ${status.pid ?: "-"}")
        appendLine("tun fd handed off: ${if (status.tunFdBridgeState == B45ATunFdBridgeState.FD_SENT) "yes" else "no"} (${status.tunFdBridgeState ?: "n/a"})")
        appendLine("protect bridge: ${status.protectBridgeState ?: "n/a"}")
        appendLine("protect requests: ${status.protectRequestCount} (failures: ${status.protectFailureCount})")
        appendLine("exit code: ${status.exitCode ?: "-"}")
        appendLine("last error: ${status.lastError ?: "-"}")
    }
}
