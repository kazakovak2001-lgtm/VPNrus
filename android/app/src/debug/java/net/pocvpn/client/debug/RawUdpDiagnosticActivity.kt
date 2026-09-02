package net.pocvpn.client.debug

import android.net.TrafficStats
import android.os.Bundle
import android.os.Process
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * B21-fix - DEBUG-ONLY, NOT Xray/QUIC. A plain ordinary UDP datagram sent
 * from this app's own UID via [DatagramSocket] - no xray-core, no
 * quic-go, no gomobile involvement at all. Exists ONLY to answer one
 * question the isolation-test evidence (identical closed-pipe/timeout
 * failure inside and outside VpnService, correlated Frankfurt firewall
 * counter staying at exactly 0) could not: does an ordinary UDP datagram
 * from this exact app UID/device/network leave the kernel at all, and does
 * it reach a real receiver.
 *
 * Sends the same fixed, non-secret marker payload ("NOVA-UDP-DIAG") to
 * three destinations - Frankfurt's real 2087/udp (the QUIC port under
 * investigation), Frankfurt's real 51820/udp (AmneziaWG's ALREADY-OPEN
 * port - reused as a same-host control so no new firewall rule is ever
 * opened; WireGuard silently drops malformed packets, so this is
 * side-effect-free), and 8.8.8.8:53 (a well-known, always-up public
 * service outside Nova's own infrastructure - a control this pass does
 * not need "operator control" over, since we only care whether the
 * datagram leaves the device, not whether 8.8.8.8 replies meaningfully).
 *
 * [TrafficStats.getUidTxBytes]/[getUidTxPackets] is real kernel-level
 * per-UID accounting, exact and immediate - not bucketed like
 * `dumpsys netstats` - and requires no special permission for the app's
 * own UID.
 */
class RawUdpDiagnosticActivity : AppCompatActivity() {

    private data class Target(val label: String, val host: String, val port: Int)

    private val targets = listOf(
        Target("Frankfurt QUIC (2087/udp)", "152.70.43.1", 2087),
        Target("Frankfurt AWG (51820/udp, already-open port)", "152.70.43.1", 51820),
        Target("8.8.8.8:53 (external control, no operator dependency)", "8.8.8.8", 53),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        val statusText = TextView(this).apply {
            text = "Sends one ordinary UDP datagram (no Xray/QUIC) per target."
        }
        root.addView(statusText)

        val runButton = Button(this).apply {
            text = "Send raw UDP diagnostic to all 3 targets"
            setOnClickListener {
                lifecycleScope.launch {
                    statusText.text = "Sending..."
                    statusText.text = runDiagnostic()
                }
            }
        }
        root.addView(runButton)
        setContentView(root)
    }

    private suspend fun runDiagnostic(): String = withContext(Dispatchers.IO) {
        val uid = Process.myUid()

        // B21-fix - control: does TrafficStats even move for this UID within
        // a short window on this device/ROM at all? A real HTTPS GET is
        // certain to transmit real bytes if general internet connectivity
        // works (already independently proven earlier this session) - if
        // TrafficStats does not move for THIS either, TrafficStats itself is
        // stale/unreliable here and the UDP result below cannot be trusted
        // as proof of zero transmission.
        val httpTxBefore = TrafficStats.getUidTxBytes(uid)
        val httpResult = try {
            val conn = URL("https://www.gstatic.com/generate_204").openConnection() as HttpsURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            val code = conn.responseCode
            conn.disconnect()
            "HTTPS control GET: succeeded, HTTP $code"
        } catch (t: Throwable) {
            "HTTPS control GET: FAILED - ${t.javaClass.simpleName}: ${t.message}"
        }
        kotlinx.coroutines.delay(500)
        val httpTxAfter = TrafficStats.getUidTxBytes(uid)
        val httpTrafficLine = "TrafficStats delta for the HTTPS control: +${httpTxAfter - httpTxBefore} bytes " +
            "(before=$httpTxBefore, after=$httpTxAfter)"

        val txBytesBefore = TrafficStats.getUidTxBytes(uid)
        val txPacketsBefore = TrafficStats.getUidTxPackets(uid)

        val payload = "NOVA-UDP-DIAG".toByteArray(Charsets.US_ASCII)
        val results = targets.map { target ->
            try {
                DatagramSocket().use { socket ->
                    socket.soTimeout = 3000
                    val packet = DatagramPacket(payload, payload.size, InetSocketAddress(target.host, target.port))
                    socket.send(packet)
                }
                "${target.label}: send() succeeded (no exception)"
            } catch (t: Throwable) {
                "${target.label}: send() FAILED - ${t.javaClass.simpleName}: ${t.message}"
            }
        }

        // Give the kernel a moment to account the sends before reading counters again.
        kotlinx.coroutines.delay(500)
        val txBytesAfter = TrafficStats.getUidTxBytes(uid)
        val txPacketsAfter = TrafficStats.getUidTxPackets(uid)

        val trafficStatsLine = if (txBytesBefore == TrafficStats.UNSUPPORTED.toLong()) {
            "TrafficStats unsupported on this device."
        } else {
            "TrafficStats delta for this UID (UDP sends): +${txBytesAfter - txBytesBefore} bytes, +${txPacketsAfter - txPacketsBefore} packets " +
                "(before=$txBytesBefore/$txPacketsBefore, after=$txBytesAfter/$txPacketsAfter)"
        }

        (listOf(httpResult, httpTrafficLine, "") + results + "" + trafficStatsLine).joinToString("\n")
    }
}
