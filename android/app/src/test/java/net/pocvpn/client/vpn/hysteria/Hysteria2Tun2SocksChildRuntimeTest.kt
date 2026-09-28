package net.pocvpn.client.vpn.hysteria

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private class FakeHysteria2Tun2SocksChildControlChannel(
    private val ackResult: Hysteria2Tun2SocksChildAck = Hysteria2Tun2SocksChildAck.Ok(pid = 4242),
) : Hysteria2Tun2SocksChildControlChannel {
    var bindCalls = 0
    var closeCalls = 0
    var lastFd = -1
    var lastMtu = -1
    var lastSocksAddr = ""
    var bindShouldThrow: Throwable? = null
    var sendStartRequestCalls = 0

    override fun bind(socketPath: File) {
        bindCalls++
        bindShouldThrow?.let { throw it }
    }

    override fun sendStartRequestAndAwaitAck(fd: Int, mtu: Int, socksAddr: String, timeoutMillis: Long): Hysteria2Tun2SocksChildAck {
        sendStartRequestCalls++
        lastFd = fd
        lastMtu = mtu
        lastSocksAddr = socksAddr
        return ackResult
    }

    override fun close() {
        closeCalls++
    }
}

private class FakeHysteria2Tun2SocksChildProcess : Hysteria2Tun2SocksChildProcess {
    var alive = true
    var requestStopCalls = 0
    var forceStopCalls = 0
    var exitCallback: ((Int) -> Unit)? = null

    /**
     * `true` (the default) makes [requestStop] synchronously fire the
     * registered exit callback - matching the real
     * `RealHysteria2Hysteria2Tun2SocksChildProcess`'s own eventual behavior (its background
     * watcher thread observes the real OS process actually exit after
     * `SIGTERM` and then fires `onExit`'s callback), just without a real
     * background thread involved. This is deliberately the "worst case"
     * ordering for the terminal-transition race tests below: the exit
     * callback fires WHILE [Hysteria2Tun2SocksChildRuntime.stop] is still
     * unwinding its own call to `stopLaunchedProcess`, reentering
     * [Hysteria2Tun2SocksChildRuntime]'s synchronized state block on the SAME
     * thread (Kotlin's `synchronized` uses a reentrant JVM monitor, so
     * this does not deadlock) - exactly the scenario `terminalClaimed`
     * exists to make safe.
     */
    var fireExitCallbackOnRequestStop = true

    override fun isAlive(): Boolean = alive
    override fun requestStop() {
        requestStopCalls++
        alive = false
        if (fireExitCallbackOnRequestStop) exitCallback?.invoke(0)
    }
    override fun forceStop() {
        forceStopCalls++
        alive = false
    }
    override fun waitForExit(timeoutMillis: Long): Int? = if (!alive) 0 else null
    override fun onExit(callback: (Int) -> Unit) {
        exitCallback = callback
    }

    /** Simulates the real watcher thread observing an UNEXPECTED exit (crash, external kill) - never preceded by our own [requestStop]. */
    fun simulateUnexpectedExit(exitCode: Int) {
        alive = false
        exitCallback?.invoke(exitCode)
    }
}

private class FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(
    private val process: FakeHysteria2Tun2SocksChildProcess = FakeHysteria2Tun2SocksChildProcess(),
) : Hysteria2Hysteria2Tun2SocksChildProcessLauncher {
    var launchCalls = 0
    var lastArgs: List<String> = emptyList()
    var launchShouldThrow: Throwable? = null

    override fun launch(binaryPath: String, args: List<String>): Hysteria2Tun2SocksChildProcess {
        launchCalls++
        lastArgs = args
        launchShouldThrow?.let { throw it }
        return process
    }
}

private class FakeHysteria2Hysteria2Tun2SocksDupFdCloser : Hysteria2Tun2SocksDupFdCloser {
    val closedFds = mutableListOf<Int>()
    override fun close(fd: Int) {
        closedFds.add(fd)
    }
}

/**
 * B46-3B lifecycle-hardening test coverage. Covers all nine of the
 * task-specified fd-ownership branches (bind failure, launch failure,
 * child-never-connects/header-send-failure/ack-timeout - all folded into
 * the control channel's own [Hysteria2Tun2SocksChildAck]/exception surface -
 * successful start, normal stop, unexpected death), the terminal-
 * transition race between stop and unexpected exit, and the pre-existing
 * repeated-start/idempotent-stop/invalid-input coverage - all exercised
 * against [Hysteria2Tun2SocksChildRuntime] with fakes, so none of this depends on
 * a real child process/SCM_RIGHTS channel/real fd being present in the
 * JVM unit test environment.
 */
class Hysteria2Tun2SocksChildRuntimeTest {

    private val controlSocketPath = File("/tmp/b46-3b-test-control.sock")

    @Test
    fun `initial state is not running`() {
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), FakeHysteria2Tun2SocksChildControlChannel())
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)
    }

    @Test
    fun `valid start succeeds, reports the childs own real pid, and never closes the handed-off fd itself`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Ok(pid = 9001))
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control, closer)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Ok(9001), result)
        assertTrue(runtime.isRunning())
        assertEquals(9001, runtime.pid)
        assertEquals(1, launcher.launchCalls)
        assertEquals(listOf(controlSocketPath.absolutePath), launcher.lastArgs)
        assertEquals(42, control.lastFd)
        assertEquals(1500, control.lastMtu)
        assertEquals("127.0.0.1:41999", control.lastSocksAddr)
        // FD ownership: once handed to the control channel, the runtime
        // itself must never also try to close it - that is the control
        // channel's own job (see RealHysteria2Hysteria2Tun2SocksChildControlChannel's own
        // ParcelFileDescriptor.adoptFd(fd).use{} doc).
        assertTrue("runtime must not close a successfully-handed-off fd itself", closer.closedFds.isEmpty())
    }

    @Test
    fun `second start while already running closes the new duplicate fd and fails without touching the launcher again`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control, closer)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val second = runtime.start(dupTunFd = 43, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertTrue(second is Hysteria2Tun2SocksChildResult.Failed)
        assertEquals(1, launcher.launchCalls)
        assertEquals(listOf(43), closer.closedFds)
    }

    @Test
    fun `invalid fd is rejected before touching the control channel or the fd closer`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), control, closer)

        val result = runtime.start(dupTunFd = -1, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Failed("invalid fd"), result)
        assertEquals(0, control.bindCalls)
        // An already-invalid fd was never ours to own - nothing to close.
        assertTrue(closer.closedFds.isEmpty())
    }

    @Test
    fun `invalid mtu closes the duplicate fd before touching the control channel`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), control, closer)

        val zero = runtime.start(dupTunFd = 42, mtu = 0, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        val negative = runtime.start(dupTunFd = 43, mtu = -1, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Failed("invalid mtu"), zero)
        assertEquals(Hysteria2Tun2SocksChildResult.Failed("invalid mtu"), negative)
        assertEquals(0, control.bindCalls)
        assertEquals(listOf(42, 43), closer.closedFds)
    }

    @Test
    fun `empty socks address closes the duplicate fd before touching the control channel`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), control, closer)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Failed("empty socks address"), result)
        assertEquals(0, control.bindCalls)
        assertEquals(listOf(42), closer.closedFds)
    }

    @Test
    fun `control channel bind failure closes the duplicate fd and never launches the process`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel().apply { bindShouldThrow = java.io.IOException("bind failed") }
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control, closer)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertTrue(result is Hysteria2Tun2SocksChildResult.Failed)
        assertEquals(1, control.bindCalls)
        assertEquals(0, launcher.launchCalls)
        assertEquals(listOf(42), closer.closedFds)
    }

    @Test
    fun `process launch failure closes the duplicate fd and closes the control channel`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher().apply { launchShouldThrow = RuntimeException("exec failed") }
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control, closer)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertTrue(result is Hysteria2Tun2SocksChildResult.Failed)
        assertEquals(1, launcher.launchCalls)
        assertEquals(1, control.closeCalls)
        assertEquals(listOf(42), closer.closedFds)
    }

    @Test
    fun `ack failure - covering child-never-connects, header-send-failure, and ack-timeout - stops the just-launched process and reports the reason`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Failed("child never connected to send the start request within 5000ms"))
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher()
        val closer = FakeHysteria2Hysteria2Tun2SocksDupFdCloser()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control, closer)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Failed("child never connected to send the start request within 5000ms"), result)
        assertFalse(runtime.isRunning())
        assertEquals(1, launcher.launchCalls)
        // The fd was already handed to (and closed/attempted by)
        // sendStartRequestAndAwaitAck itself in this branch - the runtime
        // must not ALSO try to close it (that would be the real double-
        // close this gap was about).
        assertTrue("runtime must not double-close a fd already owned by the control-channel call", closer.closedFds.isEmpty())
    }

    @Test
    fun `child returns a failure ack after engine start rejects the config`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Failed("engine start: invalid mtu"))
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher()
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control)

        val result = runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        assertEquals(Hysteria2Tun2SocksChildResult.Failed("engine start: invalid mtu"), result)
        assertFalse(runtime.isRunning())
        assertEquals(1, launcher.launchCalls)
    }

    @Test
    fun `stop before any start is a harmless no-op`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), control)

        val result = runtime.stop()

        assertTrue(result is Hysteria2Tun2SocksChildResult.Ok)
        assertEquals(1, control.closeCalls)
    }

    @Test
    fun `stop after a successful start performs graceful stop, clears state, and never reports an unexpected exit`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Ok(pid = 555))
        val process = FakeHysteria2Tun2SocksChildProcess()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(process)
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control)
        var unexpectedExitCalls = 0
        runtime.onUnexpectedExit = { unexpectedExitCalls++ }
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val result = runtime.stop()

        assertEquals(Hysteria2Tun2SocksChildResult.Ok(555), result)
        assertEquals(1, process.requestStopCalls)
        assertEquals(0, process.forceStopCalls)
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)
        // Expected stop must NEVER be misclassified as an unexpected death,
        // even though (per FakeHysteria2Tun2SocksChildProcess's own doc) the exit
        // callback fires synchronously inside requestStop() here - the
        // "worst case" ordering.
        assertEquals(0, unexpectedExitCalls)

        // A fresh start is allowed again after a stop.
        val restarted = runtime.start(dupTunFd = 44, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        assertTrue(restarted is Hysteria2Tun2SocksChildResult.Ok)
    }

    @Test
    fun `stop forces the process if it does not exit gracefully in time`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val process = object : Hysteria2Tun2SocksChildProcess {
            var stopRequested = false
            var forced = false
            override fun isAlive(): Boolean = !forced
            override fun requestStop() { stopRequested = true }
            override fun forceStop() { forced = true }
            override fun waitForExit(timeoutMillis: Long): Int? = if (forced) 137 else null
            override fun onExit(callback: (Int) -> Unit) {}
        }
        val customLauncher = object : Hysteria2Hysteria2Tun2SocksChildProcessLauncher {
            override fun launch(binaryPath: String, args: List<String>): Hysteria2Tun2SocksChildProcess = process
        }
        val runtime = Hysteria2Tun2SocksChildRuntime(customLauncher, control, gracefulStopTimeoutMillis = 10, forceStopWaitMillis = 10)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        runtime.stop()

        assertTrue(process.stopRequested)
        assertTrue(process.forced)
    }

    @Test
    fun `repeated stop is idempotent`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel()
        val runtime = Hysteria2Tun2SocksChildRuntime(FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(), control)
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        val first = runtime.stop()
        val second = runtime.stop()

        assertTrue(first is Hysteria2Tun2SocksChildResult.Ok)
        assertTrue(second is Hysteria2Tun2SocksChildResult.Ok)
        assertFalse(runtime.isRunning())
    }

    // ---- B46-3B lifecycle-hardening: unexpected child death (Gap 1) ----

    @Test
    fun `unexpected child exit notifies the owner exactly once and clears state`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Ok(pid = 777))
        val process = FakeHysteria2Tun2SocksChildProcess()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(process)
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control)
        val notifiedCodes = mutableListOf<Int>()
        runtime.onUnexpectedExit = { code -> notifiedCodes.add(code) }
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        assertTrue(runtime.isRunning())

        process.simulateUnexpectedExit(139)

        assertEquals(listOf(139), notifiedCodes)
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)
        // Control channel artifacts (socket file etc.) must be cleaned up
        // automatically too - not only on an explicit stop().
        assertEquals(1, control.closeCalls)
    }

    @Test
    fun `stop after an already-detected unexpected death is still idempotent`() {
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Ok(pid = 888))
        val process = FakeHysteria2Tun2SocksChildProcess()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(process)
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control)
        var unexpectedExitCalls = 0
        runtime.onUnexpectedExit = { unexpectedExitCalls++ }
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        process.simulateUnexpectedExit(139)
        assertEquals(1, unexpectedExitCalls)

        val stopResult = runtime.stop()

        assertTrue(stopResult is Hysteria2Tun2SocksChildResult.Ok)
        assertFalse(runtime.isRunning())
        assertEquals(null, runtime.pid)
        // stop() after an already-claimed transition must not re-fire the
        // unexpected-exit listener.
        assertEquals(1, unexpectedExitCalls)

        // A fresh start is possible after an unexpected death + stop.
        val restarted = runtime.start(dupTunFd = 44, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)
        assertTrue(restarted is Hysteria2Tun2SocksChildResult.Ok)
    }

    @Test
    fun `race - stop-initiated exit is never also reported as an unexpected exit`() {
        // FakeHysteria2Tun2SocksChildProcess.requestStop() synchronously fires the
        // exit callback by default (its own doc explains why this is the
        // meaningful "worst case" ordering to test) - this test exists
        // specifically to prove that ordering never produces a double
        // terminal transition or a false unexpected-exit report.
        val control = FakeHysteria2Tun2SocksChildControlChannel(ackResult = Hysteria2Tun2SocksChildAck.Ok(pid = 999))
        val process = FakeHysteria2Tun2SocksChildProcess()
        val launcher = FakeHysteria2Hysteria2Tun2SocksChildProcessLauncher(process)
        val runtime = Hysteria2Tun2SocksChildRuntime(launcher, control)
        var unexpectedExitCalls = 0
        runtime.onUnexpectedExit = { unexpectedExitCalls++ }
        runtime.start(dupTunFd = 42, mtu = 1500, socksAddr = "127.0.0.1:41999", binaryPath = "/fake/bin", controlSocketPath = controlSocketPath)

        runtime.stop()

        assertEquals(0, unexpectedExitCalls)
        assertFalse(runtime.isRunning())
    }
}
