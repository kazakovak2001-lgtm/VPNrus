package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.SSLSocketFactory
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

private const val AUTH_FILE_NAME = "b46-3c-auth.txt"
private const val SERVER_HOST_PORT = "16.170.208.231:34443"
private const val SERVER_PUBLIC_IP = "16.170.208.231"
private const val TEST_SNI = "b46-3c-test.local"

/**
 * B46-3C - the full physical process-isolated Hysteria2 data-plane proof
 * matrix. Each `@Test` is run individually via
 * `am instrument -e class ... -e method ...` (some, like the two
 * connection-cycle tests, are also meaningful run together). The disposable
 * server credential is read from app-private storage
 * (`filesDir/b46-3c-auth.txt`, pushed there beforehand via
 * `adb shell run-as ... sh -c 'cat > files/b46-3c-auth.txt'` - NEVER via
 * argv/`adb -e`/logcat) and passed to the service via an in-process
 * `Intent` extra, which Android does not log.
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksHysteriaDataPlaneInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use {
            it.fileDescriptor.let { fd -> java.io.FileInputStream(fd).bufferedReader().readText() }
        }

    private fun readAuth(): String = File(context.filesDir, AUTH_FILE_NAME).readText().trim()

    private fun awaitStatus(timeoutMillis: Long = 20_000): DataPlaneSpikeStatus {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var last = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
        while (System.currentTimeMillis() < deadline) {
            last = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
            if (last !is DataPlaneSpikeStatus.Idle) return last
            Thread.sleep(100)
        }
        return last
    }

    private fun awaitIdle(timeoutMillis: Long = 15_000): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value is DataPlaneSpikeStatus.Idle) return true
            Thread.sleep(100)
        }
        return false
    }

    private fun startSession(): DataPlaneSpikeStatus.Started {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        val intent = Intent(context, Tun2SocksHysteriaDataPlaneSpikeVpnService::class.java)
            .setAction(Tun2SocksHysteriaDataPlaneSpikeVpnService.ACTION_START)
            .putExtra(Tun2SocksHysteriaDataPlaneSpikeVpnService.EXTRA_SERVER, SERVER_HOST_PORT)
            .putExtra(Tun2SocksHysteriaDataPlaneSpikeVpnService.EXTRA_AUTH, readAuth())
            .putExtra(Tun2SocksHysteriaDataPlaneSpikeVpnService.EXTRA_SNI, TEST_SNI)
            .putExtra(Tun2SocksHysteriaDataPlaneSpikeVpnService.EXTRA_INSECURE, true)
        context.startService(intent)
        val status = awaitStatus()
        assertTrue("expected Started, got $status", status is DataPlaneSpikeStatus.Started)
        return status as DataPlaneSpikeStatus.Started
    }

    private fun stopSession() {
        context.startService(
            Intent(context, Tun2SocksHysteriaDataPlaneSpikeVpnService::class.java)
                .setAction(Tun2SocksHysteriaDataPlaneSpikeVpnService.ACTION_STOP),
        )
        assertTrue("expected stop to reach Idle", awaitIdle())
    }

    /** Real HTTP GET through the tunnel - this app's own socket is NOT excluded from the TUN (see the service's own doc), so this genuinely traverses TUN -> tun2socks -> SOCKS -> Hysteria -> server -> destination. */
    private fun httpGetThroughTunnel(urlStr: String): String {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        conn.connectTimeout = 15_000
        conn.readTimeout = 15_000
        return try {
            conn.inputStream.bufferedReader().readText().trim()
        } finally {
            conn.disconnect()
        }
    }

    /** Direct-IP TCP proof - no DNS involved, distinguishes DNS failure from general TCP/data-plane failure. */
    private fun directIpTlsConnect(ip: String, port: Int, sniHost: String): Boolean {
        val plain = Socket()
        plain.connect(java.net.InetSocketAddress(InetAddress.getByName(ip), port), 10_000)
        return try {
            val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(plain, sniHost, port, true)
            ssl.soTimeout = 10_000
            (ssl as javax.net.ssl.SSLSocket).startHandshake()
            val connected = ssl.session.isValid
            ssl.close()
            connected
        } finally {
            plain.close()
        }
    }

    /** Real, distinctly-UDP application-level round trip (NTP, RFC 5905 minimal client) - NOT inferred from DNS or from QUIC merely existing. */
    private fun ntpRoundTrip(host: String): Boolean {
        val addr = InetAddress.getByName(host)
        DatagramSocket().use { socket ->
            socket.soTimeout = 10_000
            val request = ByteArray(48)
            request[0] = 0x1B // LI=0, VN=3, Mode=3 (client)
            socket.send(DatagramPacket(request, request.size, addr, 123))
            val responseBuf = ByteArray(48)
            val responsePacket = DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)
            return responsePacket.length >= 48
        }
    }

    @Test
    fun cycle1_full_dataplane_proof() {
        // Xray coexistence: real Xray Go runtime loaded in THIS process
        // before the Hysteria data plane starts.
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        val started = startSession()
        val appPid = Process.myPid()
        android.util.Log.i("B46_3C", "cycle1: tun2socksPid=${started.tun2socksPid} appPid=$appPid quicConnectedAtStart=${started.quicConnected}")

        // Give the QUIC handshake a moment if it hadn't completed by the ack.
        Thread.sleep(1_000)

        // Real TCP + DNS proof + exit correlation: fetch our own exit IP.
        val exitIp = httpGetThroughTunnel("https://icanhazip.com")
        android.util.Log.i("B46_3C", "cycle1: exitIp=$exitIp")
        assertEquals("expected exit IP to match the authorized Stockholm server", SERVER_PUBLIC_IP, exitIp)

        // Direct-IP TCP proof (Cloudflare's own well-known IP, no DNS).
        val directOk = directIpTlsConnect("1.1.1.1", 443, "one.one.one.one")
        assertTrue("expected a real direct-IP TLS handshake to succeed through the tunnel", directOk)

        // Real UDP application round trip (NTP).
        val ntpOk = ntpRoundTrip("time.cloudflare.com")
        assertTrue("expected a real NTP (UDP) round trip to succeed through the tunnel", ntpOk)

        // Xray coexistence still healthy, no Go fatal anywhere.
        assertFalse(xray.isRunning)

        stopSession()
    }

    @Test
    fun cycle2_fresh_pids_full_dataplane_proof() {
        val first = startSession()
        val firstPid = first.tun2socksPid
        stopSession()

        val second = startSession()
        android.util.Log.i("B46_3C", "cycle2: firstPid=$firstPid secondPid=${second.tun2socksPid}")
        assertTrue("expected a genuinely fresh tun2socks child pid on the second cycle", second.tun2socksPid != firstPid)

        val exitIp = httpGetThroughTunnel("https://icanhazip.com")
        assertEquals(SERVER_PUBLIC_IP, exitIp)
        val ntpOk = ntpRoundTrip("time.cloudflare.com")
        assertTrue(ntpOk)

        stopSession()
    }

    @Test
    fun tun2socks_child_death_during_dataplane_tears_down_the_session() {
        val started = startSession()
        // Prove the data plane is genuinely live before killing anything.
        assertEquals(SERVER_PUBLIC_IP, httpGetThroughTunnel("https://icanhazip.com"))

        Process.sendSignal(started.tun2socksPid, 9)

        val failed = run {
            val deadline = System.currentTimeMillis() + 10_000
            var last: DataPlaneSpikeStatus = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
            while (System.currentTimeMillis() < deadline) {
                last = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
                if (last is DataPlaneSpikeStatus.Failed) return@run last
                Thread.sleep(100)
            }
            last
        }
        assertTrue("expected automatic Failed status after killing tun2socks, got $failed", failed is DataPlaneSpikeStatus.Failed)

        val tunGoneDeadline = System.currentTimeMillis() + 5_000
        var tunGone = false
        while (System.currentTimeMillis() < tunGoneDeadline) {
            if (!shell("ip link show").contains("tun0")) {
                tunGone = true
                break
            }
            Thread.sleep(100)
        }
        assertTrue("expected the TUN to be torn down automatically", tunGone)

        stopSession()
    }

    @Test
    fun hysteria_child_death_during_dataplane_tears_down_the_session() {
        startSession()
        assertEquals(SERVER_PUBLIC_IP, httpGetThroughTunnel("https://icanhazip.com"))

        // The Hysteria child's own pid is not returned by the ack protocol
        // (unmodified upstream binary, no wire-level pid report - see
        // docs/B46_3C_HYSTERIA_PROCESS_ISOLATED_DATAPLANE.md) - found via
        // `ps`, matching the binary's own resolved path.
        val psOutput = shell("ps -A -o PID,ARGS")
        val hysteriaPidLine = psOutput.lineSequence().firstOrNull { it.contains(HYSTERIA_CHILD_BINARY_FILENAME) }
        assertTrue("expected to find the running hysteria child in ps output", hysteriaPidLine != null)
        val hysteriaPid = hysteriaPidLine!!.trim().split(Regex("\\s+")).first().toInt()
        android.util.Log.i("B46_3C", "hysteria child pid=$hysteriaPid")

        Process.sendSignal(hysteriaPid, 9)

        val failed = run {
            val deadline = System.currentTimeMillis() + 10_000
            var last: DataPlaneSpikeStatus = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
            while (System.currentTimeMillis() < deadline) {
                last = Tun2SocksHysteriaDataPlaneSpikeVpnService.status.value
                if (last is DataPlaneSpikeStatus.Failed) return@run last
                Thread.sleep(100)
            }
            last
        }
        assertTrue("expected automatic Failed status after killing the hysteria child, got $failed", failed is DataPlaneSpikeStatus.Failed)

        stopSession()
    }

    /**
     * Screen-off smoke test only - per the task's own instruction, this
     * does NOT claim long-duration mobile stability, only that the
     * connection survives a real ~130s screen-off/on cycle.
     */
    @Test
    fun screen_off_smoke_test() {
        startSession()
        assertEquals(SERVER_PUBLIC_IP, httpGetThroughTunnel("https://icanhazip.com"))

        shell("input keyevent KEYCODE_SLEEP")
        Thread.sleep(130_000)
        shell("input keyevent KEYCODE_WAKEUP")
        Thread.sleep(2_000)

        val exitIpAfter = httpGetThroughTunnel("https://icanhazip.com")
        android.util.Log.i("B46_3C", "screen-off smoke: exitIpAfter=$exitIpAfter")
        assertEquals("expected the tunnel to still be usable after the screen-off interval", SERVER_PUBLIC_IP, exitIpAfter)
        val ntpOk = ntpRoundTrip("time.cloudflare.com")
        assertTrue(ntpOk)

        stopSession()
    }
}
