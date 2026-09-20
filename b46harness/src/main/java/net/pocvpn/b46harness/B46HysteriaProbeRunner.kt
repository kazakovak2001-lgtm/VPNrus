package net.pocvpn.b46harness

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.security.SecureRandom
import javax.net.ssl.HttpsURLConnection

private const val PROBE_TIMEOUT_MILLIS = 8_000
private const val DIRECT_TCP_TARGET_HOST = "1.1.1.1"
private const val DIRECT_TCP_TARGET_PORT = 443
private const val UDP_DNS_TARGET_HOST = "1.1.1.1"
private const val UDP_DNS_TARGET_PORT = 53
private const val EXIT_IP_ECHO_URL = "https://api.ipify.org"
private const val HOSTNAME_HTTPS_PROBE_URL = "https://api.ipify.org"
private const val DNS_HOSTNAME_TO_RESOLVE = "one.one.one.one"

/**
 * B46-2P - real, in-app-UID probes proving traffic actually reaches the
 * internet THROUGH the B46 TUN (never `adb shell curl`, which would run as
 * `shell`, not this app's UID, and would prove nothing about this app's own
 * socket routing - see the task's own "IN-APP PROBES" requirement). Every
 * probe here is an ORDINARY `java.net`/`javax.net.ssl` call - no manual
 * SOCKS5 pointing, because the whole point is that these ordinary sockets
 * are transparently captured by the full-tunnel TUN this service's own
 * `Builder` established (see [B46HysteriaVpnService]'s own "own-UID-included"
 * doc).
 *
 * Callers MUST gate every probe on
 * [B46HysteriaSpikePhase.FD_CONTROL_READY] having already been reached (or
 * later) - never run these against a stopped/not-yet-ready session.
 */
internal object B46HysteriaProbeRunner {

    data class DnsResult(val success: Boolean, val resolvedAddress: String?, val error: String?)
    data class HttpsResult(val success: Boolean, val exitIp: String?, val error: String?)
    data class DirectTcpResult(val success: Boolean, val error: String?)
    data class UdpDnsResult(val success: Boolean, val transactionIdMatched: Boolean, val responseBitSet: Boolean, val rcode: Int?, val error: String?)

    /** Ordinary hostname resolution through the intended TUN -> tun2socks -> Hysteria SOCKS5 path - transport-only, no leak-safety claim (see task's own DNS LEAK BOUNDARY section). */
    fun runDns(): DnsResult = try {
        val addr = InetAddress.getByName(DNS_HOSTNAME_TO_RESOLVE)
        DnsResult(success = true, resolvedAddress = addr.hostAddress, error = null)
    } catch (t: Exception) {
        DnsResult(success = false, resolvedAddress = null, error = "${t.javaClass.simpleName}: ${t.message}")
    }

    /** Hostname HTTPS request; records the returned public exit IP. */
    fun runHostnameHttps(): HttpsResult = try {
        val url = URL(HOSTNAME_HTTPS_PROBE_URL)
        val conn = url.openConnection() as HttpsURLConnection
        conn.connectTimeout = PROBE_TIMEOUT_MILLIS
        conn.readTimeout = PROBE_TIMEOUT_MILLIS
        conn.requestMethod = "GET"
        val body = BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText().trim() }
        conn.disconnect()
        HttpsResult(success = body.isNotBlank(), exitIp = body.ifBlank { null }, error = null)
    } catch (t: Exception) {
        HttpsResult(success = false, exitIp = null, error = "${t.javaClass.simpleName}: ${t.message}")
    }

    /** Direct-IP TCP connect, independent of DNS. */
    fun runDirectIpTcp(): DirectTcpResult = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByName(DIRECT_TCP_TARGET_HOST), DIRECT_TCP_TARGET_PORT), PROBE_TIMEOUT_MILLIS)
            DirectTcpResult(success = socket.isConnected, error = null)
        }
    } catch (t: Exception) {
        DirectTcpResult(success = false, error = "${t.javaClass.simpleName}: ${t.message}")
    }

    /**
     * Real UDP round trip: a well-formed DNS A-record query to 1.1.1.1:53
     * (explicitly acceptable per the task's own UDP-probe requirement).
     * Requires: matching transaction ID, response (QR) bit set, RCODE=0 -
     * never a send-only claim.
     */
    fun runUdpDns(): UdpDnsResult {
        val txnId = ByteArray(2).also { SecureRandom().nextBytes(it) }
        val query = buildDnsQuery(txnId, DNS_HOSTNAME_TO_RESOLVE)
        return try {
            DatagramSocket().use { socket ->
                socket.soTimeout = PROBE_TIMEOUT_MILLIS
                val targetAddr = InetAddress.getByName(UDP_DNS_TARGET_HOST)
                socket.send(DatagramPacket(query, query.size, targetAddr, UDP_DNS_TARGET_PORT))

                val buf = ByteArray(512)
                val packet = DatagramPacket(buf, buf.size)
                socket.receive(packet)

                val respTxnId = buf.copyOfRange(0, 2)
                val transactionIdMatched = respTxnId.contentEquals(txnId)
                val flags = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
                val responseBitSet = (flags and 0x8000) != 0
                val rcode = flags and 0x000F

                UdpDnsResult(
                    success = transactionIdMatched && responseBitSet && rcode == 0,
                    transactionIdMatched = transactionIdMatched,
                    responseBitSet = responseBitSet,
                    rcode = rcode,
                    error = null,
                )
            }
        } catch (t: Exception) {
            UdpDnsResult(success = false, transactionIdMatched = false, responseBitSet = false, rcode = null, error = "${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private fun buildDnsQuery(txnId: ByteArray, hostname: String): ByteArray {
        val labels = hostname.split(".")
        val question = labels.fold(ByteArray(0)) { acc, label ->
            acc + byteArrayOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII)
        } + byteArrayOf(0x00)
        return txnId +
            byteArrayOf(0x01, 0x00) + // flags: standard query, recursion desired
            byteArrayOf(0x00, 0x01) + // QDCOUNT=1
            byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00) + // AN/NS/AR COUNT=0
            question +
            byteArrayOf(0x00, 0x01) + // QTYPE=A
            byteArrayOf(0x00, 0x01) // QCLASS=IN
    }
}
