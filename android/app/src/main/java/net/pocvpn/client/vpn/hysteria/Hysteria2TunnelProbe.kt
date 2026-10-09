package net.pocvpn.client.vpn.hysteria

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.withTimeoutOrNull

/** Non-secret outcome of [Hysteria2TunnelProbe.confirm]; [Failed.reason] names the stage only, never a credential. */
internal sealed interface Hysteria2TunnelProbeResult {
    data object Confirmed : Hysteria2TunnelProbeResult
    data class Failed(val reason: String) : Hysteria2TunnelProbeResult
}

/**
 * Hysteria2's in-tunnel confirmation - the counterpart of Xray's B33
 * `XrayCoreController.confirmRemoteConnectivity`. The Hysteria2 child
 * reports `SOCKS5_LISTENING` only after its QUIC handshake and server auth,
 * which proves the outer path but not that a proxied stream reaches the
 * internet. This probe dials the gateway's own unauthenticated
 * `/v1/tunnel-probe` (the same path B33 uses, see
 * `XrayCoreController.TUNNEL_PROBE_PATH`) THROUGH the child's authenticated
 * loopback SOCKS5 listener, over verified HTTPS, and requires `200`.
 *
 * The app's own package is disallowed from its VPN and the probe socket goes
 * to 127.0.0.1, so it never loops through the TUN. Bounded by [timeoutMillis]:
 * on expiry the socket is closed, which unblocks the I/O thread, and the
 * result is [Hysteria2TunnelProbeResult.Failed] - never a late success.
 */
internal class Hysteria2TunnelProbe(
    private val timeoutMillis: Long = TUNNEL_PROBE_TIMEOUT_MS,
    private val tlsWrap: (Socket, String, Int) -> Socket = ::verifiedTls,
) {
    private val probeScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    suspend fun confirm(
        socksAddress: String,
        socksUsername: String,
        socksPassword: String,
        host: String,
        port: Int = TUNNEL_PROBE_PORT,
        path: String = TUNNEL_PROBE_PATH,
    ): Hysteria2TunnelProbeResult {
        val (socksHost, socksPort) = parseLoopbackSocksAddress(socksAddress)
            ?.let { it.substringBeforeLast(':') to it.substringAfterLast(':').toInt() }
            ?: return Hysteria2TunnelProbeResult.Failed("invalid local socks address")
        val socket = Socket()
        val work = probeScope.async {
            try {
                socket.soTimeout = timeoutMillis.toInt()
                socket.connect(InetSocketAddress(socksHost, socksPort), timeoutMillis.toInt())
                socks5Connect(socket.getInputStream(), socket.getOutputStream(), socksUsername, socksPassword, host, port)
                    ?.let { return@async Hysteria2TunnelProbeResult.Failed(it) }
                val stream = tlsWrap(socket, host, port)
                stream.getOutputStream().apply {
                    write("GET $path HTTP/1.1\r\nHost: $host\r\nConnection: close\r\nUser-Agent: nova\r\n\r\n".toByteArray(Charsets.US_ASCII))
                    flush()
                }
                val status = readLine(stream.getInputStream())
                if (status != null && HTTP_200.matches(status)) {
                    Hysteria2TunnelProbeResult.Confirmed
                } else {
                    Hysteria2TunnelProbeResult.Failed("unexpected http status")
                }
            } catch (t: Throwable) {
                Hysteria2TunnelProbeResult.Failed("io: ${t.javaClass.simpleName}")
            } finally {
                runCatching { socket.close() }
            }
        }
        return withTimeoutOrNull(timeoutMillis) { work.await() } ?: run {
            runCatching { socket.close() }
            work.cancel()
            Hysteria2TunnelProbeResult.Failed("timeout")
        }
    }

    companion object {
        /** Same bound as B33's `XrayCoreController.REMOTE_CONFIRM_TIMEOUT_MS`. */
        const val TUNNEL_PROBE_TIMEOUT_MS = 6_000L
        const val TUNNEL_PROBE_PORT = 443
        /** Same gateway nginx location as `XrayCoreController.TUNNEL_PROBE_PATH`. */
        const val TUNNEL_PROBE_PATH = "/v1/tunnel-probe"
        private val HTTP_200 = Regex("""^HTTP/1\.[01] 200( .*)?$""")
        private val IPV4_LITERAL = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
    }

    /** RFC 1928 + RFC 1929 username/password CONNECT. Returns null on success, else a non-secret failure stage. */
    private fun socks5Connect(input: InputStream, output: OutputStream, username: String, password: String, host: String, port: Int): String? {
        output.write(byteArrayOf(0x05, 0x01, 0x02))
        output.flush()
        val method = readExactly(input, 2)
        if (method[0].toInt() != 0x05 || method[1].toInt() != 0x02) return "socks method rejected"

        val user = username.toByteArray(Charsets.US_ASCII)
        val pass = password.toByteArray(Charsets.US_ASCII)
        if (user.size > 255 || pass.size > 255) return "socks credentials too long"
        output.write(byteArrayOf(0x01, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
        output.flush()
        val auth = readExactly(input, 2)
        if (auth[1].toInt() != 0x00) return "socks auth rejected"

        output.write(byteArrayOf(0x05, 0x01, 0x00) + encodeAddress(host) + byteArrayOf((port shr 8).toByte(), port.toByte()))
        output.flush()
        val reply = readExactly(input, 4)
        if (reply[0].toInt() != 0x05) return "socks reply malformed"
        if (reply[1].toInt() != 0x00) return "socks connect rejected: ${reply[1].toInt() and 0xff}"
        val boundLength = when (reply[3].toInt()) {
            0x01 -> 4
            0x04 -> 16
            0x03 -> readExactly(input, 1)[0].toInt() and 0xff
            else -> return "socks reply malformed"
        }
        readExactly(input, boundLength + 2)
        return null
    }

    private fun encodeAddress(host: String): ByteArray {
        IPV4_LITERAL.matchEntire(host)?.let { match ->
            val octets = match.groupValues.drop(1).map { it.toInt() }
            if (octets.all { it in 0..255 }) return byteArrayOf(0x01) + octets.map { it.toByte() }.toByteArray()
        }
        if (host.contains(':')) return byteArrayOf(0x04) + InetAddress.getByName(host).address
        val name = host.toByteArray(Charsets.US_ASCII)
        require(name.size in 1..255) { "host name length" }
        return byteArrayOf(0x03, name.size.toByte()) + name
    }

    private fun readExactly(input: InputStream, count: Int): ByteArray {
        val buffer = ByteArray(count)
        var offset = 0
        while (offset < count) {
            val read = input.read(buffer, offset, count - offset)
            if (read < 0) throw java.io.EOFException()
            offset += read
        }
        return buffer
    }

    private fun readLine(input: InputStream): String? {
        val line = StringBuilder()
        while (line.length < 512) {
            val b = input.read()
            if (b < 0) return line.takeIf { it.isNotEmpty() }?.toString()
            if (b == '\n'.code) return line.toString().trimEnd('\r')
            line.append(b.toChar())
        }
        return null
    }
}

/** Platform trust store + default hostname verifier (handles the gateway's IP-SAN certificate). */
private fun verifiedTls(raw: Socket, host: String, port: Int): Socket {
    val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, host, port, true) as SSLSocket
    ssl.startHandshake()
    if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(host, ssl.session)) {
        throw SSLPeerUnverifiedException("hostname mismatch")
    }
    return ssl
}
