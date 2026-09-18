package net.pocvpn.client.debug.b45a

import java.net.DatagramPacket
import java.net.DatagramSocket
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class B45AUdpEchoProbeTest {

    @Test
    fun `newNonce has the expected non-secret prefix`() {
        assertTrue(B45AUdpEchoProbe.newNonce().startsWith("B45A-UDP-"))
    }

    @Test
    fun `newNonce is unique across calls`() {
        assertNotEquals(B45AUdpEchoProbe.newNonce(), B45AUdpEchoProbe.newNonce())
    }

    @Test
    fun `echo destination is a hardcoded IPv4 literal never a hostname`() {
        val octets = B45AUdpEchoProbe.ECHO_HOST.split(".")
        assertEquals(4, octets.size)
        octets.forEach { octet -> assertTrue(octet.toInt() in 0..255) }
    }

    @Test
    fun `echo port differs from the shadowsocks listener port`() {
        assertNotEquals(28388, B45AUdpEchoProbe.ECHO_PORT)
    }

    @Test
    fun `round trip against an unreachable loopback port fails closed rather than matching`() {
        // No listener is bound on this port, so the socket must fail/time
        // out with matched=false - it must never report a false PASS.
        // Deliberately loopback+unbound, never the real host, so this test
        // stays deterministic and does no real network I/O.
        val unboundPort = DatagramSocket(0).use { it.localPort } // grab then release a free port
        val result = B45AUdpEchoProbe.roundTrip(
            nonce = "B45A-UDP-test-unreachable",
            host = "127.0.0.1",
            port = unboundPort,
        )
        assertTrue(!result.matched)
    }

    @Test
    fun `round trip against a real local echo returns an exact byte-for-byte match`() {
        val echo = DatagramSocket(0)
        val echoThread = Thread {
            try {
                val buf = ByteArray(256)
                val packet = DatagramPacket(buf, buf.size)
                echo.receive(packet)
                echo.send(DatagramPacket(packet.data, packet.offset, packet.length, packet.address, packet.port))
            } catch (_ : Exception) {
                // socket closed by the test after it's done - expected
            }
        }
        echoThread.start()
        try {
            val result = B45AUdpEchoProbe.roundTrip(host = "127.0.0.1", port = echo.localPort)
            assertTrue(result.matched)
        } finally {
            echo.close()
            echoThread.join(1000)
        }
    }
}
