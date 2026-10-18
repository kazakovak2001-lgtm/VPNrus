package net.pocvpn.client.vpn.hysteria

import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** H2-GATE Gap A (S1) - session scoping of the probe target and socket cleanup when a monitor cancels its probe. */
class Hysteria2SessionProbeTest {

    @Test
    fun `the probe target is served only for its own session and cleared with it`() {
        Hysteria2VpnService.probeTarget = Hysteria2VpnService.Companion.ProbeTarget(7L, "127.0.0.1:4000", "u", "p", "gw")
        try {
            assertEquals("gw", Hysteria2VpnService.probeTarget(7L)?.host)
            assertNull(Hysteria2VpnService.probeTarget(6L))
            Hysteria2VpnService.clearDataPlaneSource(6L)
            assertEquals("a stale session must not clear the current target", "gw", Hysteria2VpnService.probeTarget(7L)?.host)
            Hysteria2VpnService.clearDataPlaneSource(7L)
            assertNull(Hysteria2VpnService.probeTarget(7L))
        } finally {
            Hysteria2VpnService.probeTarget = null
        }
    }

    @Test
    fun `cancelling the caller closes the probe socket at once instead of waiting for the timeout`() = runBlocking {
        // A local listener that accepts and never answers: the probe blocks reading the SOCKS reply.
        ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { server ->
            val created = AtomicReference<Socket>()
            val probe = Hysteria2TunnelProbe(timeoutMillis = 30_000L, socketFactory = { Socket().also { created.set(it) } })
            val call = async(Dispatchers.Default) { probe.confirm("127.0.0.1:${server.localPort}", "u", "p", "gw") }
            val accepted = server.accept()
            delay(200)
            call.cancel()
            val start = System.nanoTime()
            while (created.get()?.isClosed != true && System.nanoTime() - start < 2_000_000_000L) delay(10)
            assertTrue("probe socket closed promptly after cancellation", created.get().isClosed)
            accepted.close()
        }
    }
}
