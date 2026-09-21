package net.pocvpn.client.vpn.hysteria

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private class FakeHysteriaProtectBridge : HysteriaProtectBridge {
    var startCalls = 0
    var stopCalls = 0
    override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
        startCalls++
    }
    override fun stop() {
        stopCalls++
    }
}

private class FakeHysteriaChildProcess : HysteriaChildProcess, LogLineObservable {
    var alive = true
    var requestStopCalls = 0
    var forceStopCalls = 0
    private var exitCallback: ((Int) -> Unit)? = null
    private val logLineListeners = mutableListOf<(String) -> Unit>()

    override fun isAlive(): Boolean = alive
    override fun requestStop() { requestStopCalls++; alive = false }
    override fun forceStop() { forceStopCalls++; alive = false }
    override fun waitForExit(timeoutMillis: Long): Int? = if (!alive) 0 else null
    override fun onExit(callback: (Int) -> Unit) { exitCallback = callback }
    override fun addLogLineListener(listener: (String) -> Unit) { logLineListeners.add(listener) }

    fun emitLine(line: String) {
        logLineListeners.forEach { it(line) }
    }

    fun simulateUnexpectedExit(code: Int) {
        alive = false
        exitCallback?.invoke(code)
    }
}

private class FakeHysteriaChildProcessLauncher(
    private val process: FakeHysteriaChildProcess = FakeHysteriaChildProcess(),
    private val readyLineOnLaunch: String? = "SOCKS5_LISTENING addr=127.0.0.1:41080",
) : HysteriaChildProcessLauncher {
    var launchCalls = 0
    override fun launch(binaryPath: String, args: List<String>): HysteriaChildProcess {
        launchCalls++
        // Real RealHysteriaChildProcessLauncher's stdout-drain thread would
        // eventually emit the child's own readiness line asynchronously -
        // simulated here on a background thread too, so start()'s real
        // CountDownLatch.await() codepath is genuinely exercised, not
        // bypassed.
        readyLineOnLaunch?.let { line ->
            Thread { Thread.sleep(20); process.emitLine(line) }.apply { isDaemon = true }.start()
        }
        return process
    }
}

class HysteriaChildRuntimeTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private val config = HysteriaChildConfig(server = "127.0.0.1:34443", auth = "test-auth", sni = "test.local", insecure = true, socksListen = "127.0.0.1:41080")

    @Test
    fun `valid start succeeds once the child reports SOCKS5_LISTENING`() {
        val protect = FakeHysteriaProtectBridge()
        val launcher = FakeHysteriaChildProcessLauncher()
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)

        val result = runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is HysteriaChildResult.Ok)
        assertTrue(runtime.isRunning())
        assertTrue(runtime.socksReady)
        assertEquals(1, launcher.launchCalls)
        assertEquals(1, protect.startCalls)
    }

    @Test
    fun `start fails if the child never reports readiness within the timeout`() {
        val protect = FakeHysteriaProtectBridge()
        val launcher = FakeHysteriaChildProcessLauncher(readyLineOnLaunch = null)
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 200)

        val result = runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is HysteriaChildResult.Failed)
        assertFalse(runtime.isRunning())
        assertEquals(1, protect.stopCalls)
    }

    @Test
    fun `config file is written and deleted on stop, never left behind`() {
        val protect = FakeHysteriaProtectBridge()
        val launcher = FakeHysteriaChildProcessLauncher()
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        val workDir = tempFolder.newFolder("work")

        runtime.start(config, "/fake/bin", workDir) { true }
        val configFile = File(workDir, "b46-3c-hysteria-config.json")
        assertTrue("expected the config file to exist while running", configFile.exists())

        runtime.stop()
        assertFalse("expected the config file to be deleted on stop", configFile.exists())
    }

    @Test
    fun `repeated start while running is rejected`() {
        val protect = FakeHysteriaProtectBridge()
        val launcher = FakeHysteriaChildProcessLauncher()
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        val second = runtime.start(config, "/fake/bin", tempFolder.newFolder("work2")) { true }

        assertTrue(second is HysteriaChildResult.Failed)
        assertEquals(1, launcher.launchCalls)
    }

    @Test
    fun `stop is idempotent`() {
        val protect = FakeHysteriaProtectBridge()
        val launcher = FakeHysteriaChildProcessLauncher()
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        runtime.stop()
        runtime.stop()

        assertFalse(runtime.isRunning())
    }

    @Test
    fun `unexpected child exit notifies the owner exactly once and cleans up artifacts`() {
        val protect = FakeHysteriaProtectBridge()
        val process = FakeHysteriaChildProcess()
        val launcher = FakeHysteriaChildProcessLauncher(process)
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        val notified = mutableListOf<Int>()
        runtime.onUnexpectedExit = { code -> notified.add(code) }
        val workDir = tempFolder.newFolder("work")
        runtime.start(config, "/fake/bin", workDir) { true }

        process.simulateUnexpectedExit(137)

        assertEquals(listOf(137), notified)
        assertFalse(runtime.isRunning())
        assertFalse(File(workDir, "b46-3c-hysteria-config.json").exists())
    }

    @Test
    fun `stop after unexpected death is still idempotent and never double-notifies`() {
        val protect = FakeHysteriaProtectBridge()
        val process = FakeHysteriaChildProcess()
        val launcher = FakeHysteriaChildProcessLauncher(process)
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        var notifiedCount = 0
        runtime.onUnexpectedExit = { notifiedCount++ }
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        process.simulateUnexpectedExit(137)
        assertEquals(1, notifiedCount)

        val stopResult = runtime.stop()

        assertTrue(stopResult is HysteriaChildResult.Ok)
        assertEquals(1, notifiedCount)
    }

    @Test
    fun `protector callback is forwarded from the protect bridge`() {
        var receivedFd = -1
        val protect = object : HysteriaProtectBridge {
            override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
                receivedFd = if (protector(42)) 42 else -1
            }
            override fun stop() {}
        }
        val launcher = FakeHysteriaChildProcessLauncher()
        val runtime = HysteriaChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)

        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { fd -> fd == 42 }

        assertEquals(42, receivedFd)
    }
}
