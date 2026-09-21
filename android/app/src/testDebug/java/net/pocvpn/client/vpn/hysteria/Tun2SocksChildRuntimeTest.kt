package net.pocvpn.client.vpn.hysteria

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeTun2SocksChildControlChannel(
    private val ackResult: Tun2SocksChildAck = Tun2SocksChildAck.Ok(pid = 4242),
) : Tun2SocksChildControlChannel {
    var bindCalls = 0
    var closeCalls = 0
    var lastFd = -1
    var lastMtu = -1
    var lastSocksAddr = ""

    override fun bind(socketPath: File) {
        bindCalls++
    }

    override fun sendStartRequestAndAwaitAck(fd: Int, mtu: Int, socksAddr: String, timeoutMillis: Long): Tun2SocksChildAck {
        lastFd = fd
        lastMtu = mtu
        lastSocksAddr = socksAddr
        return ackResult
    }

    override fun close() {
        closeCalls++
    }
}

private class FakeTun2SocksChildProcess : Tun2SocksChildProcess {
    var alive = true
    var requestStopCalls = 0
    var forceStopCalls = 0

    override fun isAlive(): Boolean = alive
    override fun requestStop() {
        requestStopCalls++
        alive = false
    }
    override fun forceStop() {
        forceStopCalls++
        alive = false
    }
    override fun waitForExit(timeoutMillis: Long): Int? = if (!alive) 0 else null
    override fun onExit(callback: (Int) -> Unit) {}
}

private class FakeTun2SocksChildProcessLauncher(
    private val process: FakeTun2SocksChildProcess = FakeTun2SocksChildProcess(),
) : Tun2SocksChildProcessLauncher {
    var launchCalls = 0
    var lastArgs: List<String> = emptyList()

    override fun launch(binaryPath: String, args: List<String>): Tun2SocksChildProcess {
        launchCalls++
        lastArgs = args
        return process
    }
}

/**
 * B46-3B test coverage: repeated-start rejection, stop idempotency,
 * invalid fd/mtu/socks-address, ack-mapping (both success and failure),
 * and graceful-then-forceful stop - all exercised against
 * [Tun2SocksChildRuntime] with fakes, so none of this depends on a real
 * child process/SCM_RIGHTS channel being present in the JVM unit test
 * environment.
 */
class Tun2SocksChildRuntimeTest {

    private val controlSocketPath = File("/tmp/b46-3b-test-control.sock")

    @Test
    fun `initial state is not running`() {
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), FakeTun2SocksChildControlChannel())
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)
    }

    @Test
    fun `valid start succeeds and reports the childs own real pid`() {
        val control = FakeTun2SocksChildControlChannel(ackResult = Tun2SocksChildAck.Ok(pid = 9001))
        val launcher = FakeTun2SocksChildProcessLauncher()
        val runtime = Tun2SocksChildRuntime(launcher, control)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Tun2SocksChildResult.Ok(9001), result)
        assertTrue(runtime.isRunning())
        assertEquals(9001, runtime.pid)
        assertEquals(1, launcher.launchCalls)
        assertEquals(listOf(controlSocketPath.absolutePath), launcher.lastArgs)
        assertEquals(42, control.lastFd)
        assertEquals(1500, control.lastMtu)
        assertEquals("127.0.0.1:41999", control.lastSocksAddr)
    }

    @Test
    fun `second start while already running fails deterministically without touching the launcher again`() {
        val control = FakeTun2SocksChildControlChannel()
        val launcher = FakeTun2SocksChildProcessLauncher()
        val runtime = Tun2SocksChildRuntime(launcher, control)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val second = runtime.start(dupTunFd = 43, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertTrue(second is Tun2SocksChildResult.Failed)
        assertEquals(1, launcher.launchCalls)
    }

    @Test
    fun `invalid fd is rejected before touching the control channel`() {
        val control = FakeTun2SocksChildControlChannel()
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), control)

        val result = runtime.start(dupTunFd = -1, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Tun2SocksChildResult.Failed("invalid fd"), result)
        assertEquals(0, control.bindCalls)
    }

    @Test
    fun `invalid mtu is rejected before touching the control channel`() {
        val control = FakeTun2SocksChildControlChannel()
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), control)

        val zero = runtime.start(dupTunFd = 42, mtu = 0, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        val negative = runtime.start(dupTunFd = 42, mtu = -1, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Tun2SocksChildResult.Failed("invalid mtu"), zero)
        assertEquals(Tun2SocksChildResult.Failed("invalid mtu"), negative)
        assertEquals(0, control.bindCalls)
    }

    @Test
    fun `empty socks address is rejected before touching the control channel`() {
        val control = FakeTun2SocksChildControlChannel()
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), control)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Tun2SocksChildResult.Failed("empty socks address"), result)
        assertEquals(0, control.bindCalls)
    }

    @Test
    fun `ack failure stops the just-launched process and reports the reason`() {
        val control = FakeTun2SocksChildControlChannel(ackResult = Tun2SocksChildAck.Failed("engine start: invalid mtu"))
        val launcher = FakeTun2SocksChildProcessLauncher()
        val runtime = Tun2SocksChildRuntime(launcher, control)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Tun2SocksChildResult.Failed("engine start: invalid mtu"), result)
        assertFalse(runtime.isRunning())
        assertEquals(1, launcher.launchCalls)
    }

    @Test
    fun `stop before any start is a harmless no-op`() {
        val control = FakeTun2SocksChildControlChannel()
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), control)

        val result = runtime.stop()

        assertTrue(result is Tun2SocksChildResult.Ok)
        assertEquals(1, control.closeCalls)
    }

    @Test
    fun `stop after a successful start performs graceful stop then clears state`() {
        val control = FakeTun2SocksChildControlChannel(ackResult = Tun2SocksChildAck.Ok(pid = 555))
        val process = FakeTun2SocksChildProcess()
        val launcher = FakeTun2SocksChildProcessLauncher(process)
        val runtime = Tun2SocksChildRuntime(launcher, control)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val result = runtime.stop()

        assertEquals(Tun2SocksChildResult.Ok(555), result)
        assertEquals(1, process.requestStopCalls)
        assertEquals(0, process.forceStopCalls)
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)

        // A fresh start is allowed again after a stop.
        val restarted = runtime.start(dupTunFd = 44, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        assertTrue(restarted is Tun2SocksChildResult.Ok)
    }

    @Test
    fun `stop forces the process if it does not exit gracefully in time`() {
        val control = FakeTun2SocksChildControlChannel()
        val process = object : Tun2SocksChildProcess {
            var stopRequested = false
            var forced = false
            override fun isAlive(): Boolean = !forced
            override fun requestStop() { stopRequested = true }
            override fun forceStop() { forced = true }
            override fun waitForExit(timeoutMillis: Long): Int? = if (forced) 137 else null
            override fun onExit(callback: (Int) -> Unit) {}
        }
        val customLauncher = object : Tun2SocksChildProcessLauncher {
            override fun launch(binaryPath: String, args: List<String>): Tun2SocksChildProcess = process
        }
        val runtime = Tun2SocksChildRuntime(customLauncher, control, gracefulStopTimeoutMillis = 10, forceStopWaitMillis = 10)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        runtime.stop()

        assertTrue(process.stopRequested)
        assertTrue(process.forced)
    }

    @Test
    fun `repeated stop is idempotent`() {
        val control = FakeTun2SocksChildControlChannel()
        val runtime = Tun2SocksChildRuntime(FakeTun2SocksChildProcessLauncher(), control)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val first = runtime.stop()
        val second = runtime.stop()

        assertTrue(first is Tun2SocksChildResult.Ok)
        assertTrue(second is Tun2SocksChildResult.Ok)
        assertFalse(runtime.isRunning())
    }
}
