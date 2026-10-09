package net.pocvpn.client.vpn.hysteria

import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlinx.coroutines.runBlocking
import net.pocvpn.client.vpn.TransportState
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [Hysteria2TunnelProbe] against an in-JVM fake of the Hysteria2 child's
 * loopback SOCKS5 listener. TLS is replaced by the identity wrap (plain HTTP)
 * - the SOCKS5/HTTP framing, credential use and bounds are what is tested.
 */
class Hysteria2TunnelProbeTest {

    private data class Observed(val username: String, val password: String, val atyp: Int, val address: String, val port: Int, val requestLine: String)

    private val server = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
    private val observed = AtomicReference<Observed?>(null)
    private val socksAddress = "127.0.0.1:${server.localPort}"
    private val plain: (Socket, String, Int) -> Socket = { socket, _, _ -> socket }

    @After
    fun tearDown() {
        server.close()
    }

    private fun serveOnce(
        acceptAuth: Boolean = true,
        connectReply: Int = 0x00,
        httpStatusLine: String? = "HTTP/1.1 200 OK",
    ) {
        thread(isDaemon = true) {
            runCatching {
                server.accept().use { client ->
                    val input = DataInputStream(client.getInputStream())
                    val output = client.getOutputStream()
                    input.readFully(ByteArray(3))
                    output.write(byteArrayOf(0x05, 0x02))
                    input.readUnsignedByte()
                    val username = String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                    val password = String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                    output.write(byteArrayOf(0x01, if (acceptAuth) 0x00 else 0x01))
                    if (!acceptAuth) return@thread
                    input.readFully(ByteArray(3))
                    val atyp = input.readUnsignedByte()
                    val address = when (atyp) {
                        0x01 -> ByteArray(4).also { input.readFully(it) }.joinToString(".") { (it.toInt() and 0xff).toString() }
                        0x03 -> String(ByteArray(input.readUnsignedByte()).also { input.readFully(it) })
                        else -> error("unexpected atyp $atyp")
                    }
                    val port = input.readUnsignedShort()
                    output.write(byteArrayOf(0x05, connectReply.toByte(), 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90.toByte()))
                    if (connectReply != 0x00) return@thread
                    val requestLine = client.getInputStream().bufferedReader().readLine()
                    observed.set(Observed(username, password, atyp, address, port, requestLine))
                    if (httpStatusLine == null) {
                        Thread.sleep(5_000)
                    } else {
                        output.write("$httpStatusLine\r\nContent-Length: 3\r\n\r\nok\n".toByteArray())
                    }
                    output.flush()
                }
            }
        }
    }

    private fun probe(timeoutMillis: Long = 2_000L) = Hysteria2TunnelProbe(timeoutMillis = timeoutMillis, tlsWrap = plain)

    @Test
    fun `200 through the authenticated socks hop confirms the tunnel`() = runBlocking {
        serveOnce()
        val result = probe().confirm(socksAddress, "user1", "pass1", "16.170.208.231")
        assertEquals(Hysteria2TunnelProbeResult.Confirmed, result)
        val seen = observed.get()!!
        assertEquals("user1", seen.username)
        assertEquals("pass1", seen.password)
        assertEquals(0x01, seen.atyp)
        assertEquals("16.170.208.231", seen.address)
        assertEquals(443, seen.port)
        assertEquals("GET /v1/tunnel-probe HTTP/1.1", seen.requestLine)
    }

    @Test
    fun `a host name is sent as a socks domain address, resolved remotely`() = runBlocking {
        serveOnce()
        val result = probe().confirm(socksAddress, "u", "p", "origin-sthlm.example")
        assertEquals(Hysteria2TunnelProbeResult.Confirmed, result)
        assertEquals(0x03, observed.get()!!.atyp)
        assertEquals("origin-sthlm.example", observed.get()!!.address)
    }

    @Test
    fun `rejected socks credentials fail`() = runBlocking {
        serveOnce(acceptAuth = false)
        assertEquals(Hysteria2TunnelProbeResult.Failed("socks auth rejected"), probe().confirm(socksAddress, "u", "p", "16.170.208.231"))
    }

    @Test
    fun `a socks connect error from the child fails`() = runBlocking {
        serveOnce(connectReply = 0x05)
        assertEquals(Hysteria2TunnelProbeResult.Failed("socks connect rejected: 5"), probe().confirm(socksAddress, "u", "p", "16.170.208.231"))
    }

    @Test
    fun `a non-200 response fails`() = runBlocking {
        serveOnce(httpStatusLine = "HTTP/1.1 503 Service Unavailable")
        assertEquals(Hysteria2TunnelProbeResult.Failed("unexpected http status"), probe().confirm(socksAddress, "u", "p", "16.170.208.231"))
    }

    @Test
    fun `a stalled tunnel fails at the deadline, never later`() = runBlocking {
        serveOnce(httpStatusLine = null)
        val started = System.nanoTime()
        val result = probe(timeoutMillis = 300L).confirm(socksAddress, "u", "p", "16.170.208.231")
        val elapsedMillis = (System.nanoTime() - started) / 1_000_000
        assertTrue("expected failure, got $result", result is Hysteria2TunnelProbeResult.Failed)
        assertTrue("took $elapsedMillis ms", elapsedMillis < 2_000)
    }

    @Test
    fun `a non-loopback socks address is refused without dialing`() = runBlocking {
        assertEquals(
            Hysteria2TunnelProbeResult.Failed("invalid local socks address"),
            probe().confirm("10.0.0.1:1080", "u", "p", "16.170.208.231"),
        )
    }

    @Test
    fun `a probe failure maps to a transport error naming the stage`() {
        val state = hysteria2TransportStateFor(Hysteria2RuntimePhase.FAILED, Hysteria2RuntimeError.RemoteUnconfirmed("timeout"))
        assertEquals("Hysteria2 in-tunnel probe failed: timeout", (state as TransportState.Error).message)
    }
}
