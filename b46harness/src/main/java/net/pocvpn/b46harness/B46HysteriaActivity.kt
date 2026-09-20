package net.pocvpn.b46harness

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val VPN_PERMISSION_REQUEST_CODE = 4601
private const val TAG = "B46HysteriaActivity"

/**
 * B46-2P - DEBUG/RESEARCH ONLY, NOT A PRODUCTION TRANSPORT UI.
 *
 * Manual entry point for [B46HysteriaVpnService], mirroring the isolation
 * approach of [net.pocvpn.client.debug.b45a.B45ASpikeActivity] (a separate,
 * debug-only entry point in `:app`) - here achieved by being a whole
 * separate application (see build.gradle.kts) rather than a `debug`
 * source-set fragment. Launchable normally, or via `adb shell am start`.
 */
class B46HysteriaActivity : ComponentActivity() {

    private lateinit var statusText: TextView
    private lateinit var probeResultText: TextView
    private var currentStatus: B46HysteriaSpikeStatus = B46HysteriaSpikeStatus.IDLE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }

        statusText = TextView(this).apply { text = "B46-2P - not started" }
        root.addView(statusText)

        root.addView(
            Button(this).apply {
                text = "B46 Start"
                setOnClickListener { requestVpnPermissionThenStart(B46HysteriaVpnService.ACTION_START) }
            },
        )
        root.addView(
            Button(this).apply {
                text = "B46 Start (CONTROLLED PROTECT-FAILURE TEST)"
                setOnClickListener { requestVpnPermissionThenStart(B46HysteriaVpnService.ACTION_START_PROTECT_FAILURE_TEST) }
            },
        )
        root.addView(
            Button(this).apply {
                text = "B46 Stop"
                setOnClickListener {
                    startService(Intent(this@B46HysteriaActivity, B46HysteriaVpnService::class.java).setAction(B46HysteriaVpnService.ACTION_STOP))
                }
            },
        )
        root.addView(
            Button(this).apply {
                text = "Run Probes (DNS / HTTPS / Direct-IP TCP / UDP)"
                setOnClickListener { runProbes() }
            },
        )
        root.addView(
            Button(this).apply {
                text = "Mark DATA_PLANE_READY (after probes pass)"
                setOnClickListener { markDataPlaneReadyIfProbesPassed() }
            },
        )

        probeResultText = TextView(this).apply { text = "probes: not run" }
        root.addView(probeResultText)

        setContentView(ScrollView(this).apply { addView(root) })

        lifecycleScope.launch {
            B46HysteriaVpnService.status.collect { status ->
                currentStatus = status
                statusText.text = renderStatus(status)
            }
        }
    }

    private var lastProbesAllPassed = false

    private fun runProbes() {
        if (currentStatus.phase != B46HysteriaSpikePhase.FD_CONTROL_READY && currentStatus.phase != B46HysteriaSpikePhase.DATA_PLANE_READY) {
            probeResultText.text = "probes: REFUSED - phase is ${currentStatus.phase}, need FD_CONTROL_READY or later"
            return
        }
        probeResultText.text = "probes: running ..."
        lifecycleScope.launch {
            val dnsR = withContext(Dispatchers.IO) { B46HysteriaProbeRunner.runDns() }
            val httpsR = withContext(Dispatchers.IO) { B46HysteriaProbeRunner.runHostnameHttps() }
            val tcpR = withContext(Dispatchers.IO) { B46HysteriaProbeRunner.runDirectIpTcp() }
            val udpR = withContext(Dispatchers.IO) { B46HysteriaProbeRunner.runUdpDns() }

            lastProbesAllPassed = dnsR.success && httpsR.success && tcpR.success && udpR.success

            probeResultText.text = buildString {
                appendLine("DNS: success=${dnsR.success} resolved=${dnsR.resolvedAddress} error=${dnsR.error ?: "-"}")
                appendLine("HTTPS: success=${httpsR.success} exitIp=${httpsR.exitIp} error=${httpsR.error ?: "-"}")
                appendLine("Direct-IP TCP: success=${tcpR.success} error=${tcpR.error ?: "-"}")
                appendLine(
                    "UDP(DNS 1.1.1.1:53): success=${udpR.success} txnIdMatch=${udpR.transactionIdMatched} " +
                        "responseBit=${udpR.responseBitSet} rcode=${udpR.rcode} error=${udpR.error ?: "-"}",
                )
                appendLine("overall: ${if (lastProbesAllPassed) "ALL PASS" else "FAIL"}")
            }
            Log.i(TAG, "probe results: dns=$dnsR https=$httpsR tcp=$tcpR udp=$udpR")
        }
    }

    private fun markDataPlaneReadyIfProbesPassed() {
        if (!lastProbesAllPassed) {
            probeResultText.text = (probeResultText.text as CharSequence).toString() +
                "\nREFUSED: cannot mark DATA_PLANE_READY - probes have not all passed yet."
            return
        }
        startService(Intent(this, B46HysteriaVpnService::class.java).setAction(B46HysteriaVpnService.ACTION_MARK_DATA_PLANE_READY))
        probeResultText.text = (probeResultText.text as CharSequence).toString() +
            "\nProbes passed - requested DATA_PLANE_READY (see phase above)."
    }

    private fun requestVpnPermissionThenStart(action: String) {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            pendingStartAction = action
            startActivityForResult(prepareIntent, VPN_PERMISSION_REQUEST_CODE)
        } else {
            startService(Intent(this, B46HysteriaVpnService::class.java).setAction(action))
        }
    }

    private var pendingStartAction: String? = null

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_PERMISSION_REQUEST_CODE && resultCode == RESULT_OK) {
            val action = pendingStartAction ?: B46HysteriaVpnService.ACTION_START
            startService(Intent(this, B46HysteriaVpnService::class.java).setAction(action))
        }
    }

    private fun renderStatus(status: B46HysteriaSpikeStatus): String = buildString {
        appendLine("B46-2P - DEBUG/RESEARCH ONLY, NOT A PRODUCTION TRANSPORT")
        appendLine("phase: ${status.phase}")
        appendLine("runtime pid: ${status.runtimePid ?: "-"}")
        appendLine("protect requests: ${status.fdControlRequestCount} (failures: ${status.fdControlFailureCount})")
        appendLine("quic handshake connected: ${status.quicHandshakeConnected}")
        appendLine("socks5 listener ready: ${status.socksListenerReady}")
        appendLine("exit code: ${status.exitCode ?: "-"}")
        appendLine("last error: ${status.lastError ?: "-"}")
    }
}
