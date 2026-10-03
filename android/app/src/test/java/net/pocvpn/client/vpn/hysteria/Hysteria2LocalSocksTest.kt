package net.pocvpn.client.vpn.hysteria

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** B46-4A - per-session local SOCKS credentials and the loopback address parsers. */
class Hysteria2LocalSocksTest {

    private val hex = Regex("[0-9a-f]+")

    @Test
    fun `every generated credential pair is fresh`() {
        val generated = List(500) { Hysteria2LocalSocksCredentials.generate() }
        assertEquals(500, generated.map { it.username }.toSet().size)
        assertEquals(500, generated.map { it.password }.toSet().size)
        generated.forEach { assertNotEquals(it.username, it.password) }
    }

    @Test
    fun `credentials carry 128-bit username and 256-bit password entropy as lowercase hex`() {
        val c = Hysteria2LocalSocksCredentials.generate()
        assertEquals(Hysteria2LocalSocksCredentials.USERNAME_BYTES * 2, c.username.length)
        assertEquals(Hysteria2LocalSocksCredentials.PASSWORD_BYTES * 2, c.password.length)
        assertTrue(hex.matches(c.username))
        assertTrue(hex.matches(c.password))
        assertEquals(16, Hysteria2LocalSocksCredentials.USERNAME_BYTES)
        assertEquals(32, Hysteria2LocalSocksCredentials.PASSWORD_BYTES)
    }

    @Test
    fun `credentials toString is redacted`() {
        val c = Hysteria2LocalSocksCredentials.generate()
        val text = c.toString()
        assertFalse(text.contains(c.username))
        assertFalse(text.contains(c.password))
    }

    @Test
    fun `the child listens on an ephemeral loopback port, never the old fixed 41080`() {
        assertEquals("127.0.0.1:0", LOCAL_SOCKS_LISTEN)
    }

    @Test
    fun `loopback socks address parser accepts only 127_0_0_1 with a non-zero port`() {
        assertEquals("127.0.0.1:1", parseLoopbackSocksAddress("127.0.0.1:1"))
        assertEquals("127.0.0.1:65535", parseLoopbackSocksAddress("127.0.0.1:65535"))
        for (bad in listOf(
            "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:", "127.0.0.1", "0.0.0.0:1080", "127.0.0.2:1080",
            "localhost:1080", "[::1]:1080", "10.0.0.1:1080", " 127.0.0.1:1080", "127.0.0.1:1080x", "",
        )) {
            assertNull(bad, parseLoopbackSocksAddress(bad))
        }
    }

    @Test
    fun `SOCKS5_LISTENING line parser extracts the bound address after the log prefix`() {
        assertEquals("127.0.0.1:43210", parseSocksListeningLine("2026/10/02 12:00:00 SOCKS5_LISTENING addr=127.0.0.1:43210 auth=required"))
        assertEquals("127.0.0.1:43210", parseSocksListeningLine("SOCKS5_LISTENING addr=127.0.0.1:43210 auth=required"))
        for (bad in listOf(
            "SOCKS5_LISTENING addr=0.0.0.0:43210 auth=required", "SOCKS5_LISTENING addr=127.0.0.1:0 auth=required",
            "SOCKS5_LISTENING addr=[::1]:43210 auth=required", "SOCKS5_LISTENING auth=required", "SOCKS5_LISTENING addr=",
            "connected: udpEnabled=true", "",
        )) {
            assertNull(bad, parseSocksListeningLine(bad))
        }
    }

    @Test
    fun `a pre-hardening child line without the auth=required marker is refused`() {
        assertNull(parseSocksListeningLine("SOCKS5_LISTENING addr=127.0.0.1:41080"))
        assertNull(parseSocksListeningLine("2026/09/28 10:00:00 SOCKS5_LISTENING addr=127.0.0.1:43210"))
        assertNull(parseSocksListeningLine("SOCKS5_LISTENING addr=127.0.0.1:43210 auth=none"))
    }

    @Test
    fun `tun2socks ack must carry the socksAuth capability marker`() {
        assertEquals(Hysteria2Tun2SocksChildAck.Ok(pid = 77), parseTun2SocksChildAck("""{"ok":true,"pid":77,"socksAuth":true}"""))
        assertTrue(parseTun2SocksChildAck("""{"ok":true,"pid":77}""") is Hysteria2Tun2SocksChildAck.Failed)
        assertTrue(parseTun2SocksChildAck("""{"ok":true,"pid":77,"socksAuth":false}""") is Hysteria2Tun2SocksChildAck.Failed)
        assertEquals(
            Hysteria2Tun2SocksChildAck.Failed("engine start: boom"),
            parseTun2SocksChildAck("""{"ok":false,"error":"engine start: boom"}"""),
        )
        assertTrue(parseTun2SocksChildAck("not json") is Hysteria2Tun2SocksChildAck.Failed)
    }
}
