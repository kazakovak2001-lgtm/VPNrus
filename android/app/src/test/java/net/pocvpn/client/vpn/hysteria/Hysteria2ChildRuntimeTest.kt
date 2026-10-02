package net.pocvpn.client.vpn.hysteria

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private class FakeHysteria2ProtectBridge : Hysteria2ProtectBridge {
    var startCalls = 0
    var stopCalls = 0
    override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
        startCalls++
    }
    override fun stop() {
        stopCalls++
    }
}

private class FakeHysteria2ChildProcess : Hysteria2ChildProcess, LogLineObservable {
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

private class FakeHysteria2ChildProcessLauncher(
    private val process: FakeHysteria2ChildProcess = FakeHysteria2ChildProcess(),
    private val readyLineOnLaunch: String? = "SOCKS5_LISTENING addr=127.0.0.1:41080 auth=required",
) : Hysteria2ChildProcessLauncher {
    var launchCalls = 0
    override fun launch(binaryPath: String, args: List<String>): Hysteria2ChildProcess {
        launchCalls++
        // Real RealHysteria2ChildProcessLauncher's stdout-drain thread would
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

class Hysteria2ChildRuntimeTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    // insecure = false - see Hysteria2ChildConfig.insecure's own hard
    // production gate: this runtime refuses to launch a child at all when
    // insecure is true (see the dedicated test below).
    private val config = Hysteria2ChildConfig(server = "127.0.0.1:34443", auth = "test-auth", sni = "test.local", insecure = false, socksListen = LOCAL_SOCKS_LISTEN, socksUsername = "test-socks-user", socksPassword = "test-socks-pass")

    @Test
    fun `valid start succeeds once the child reports SOCKS5_LISTENING`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)

        val result = runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is Hysteria2ChildResult.Ok)
        assertTrue(runtime.isRunning())
        assertTrue(runtime.socksReady)
        assertEquals(1, launcher.launchCalls)
        assertEquals(1, protect.startCalls)
    }

    @Test
    fun `start fails if the child never reports readiness within the timeout`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher(readyLineOnLaunch = null)
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 200)

        val result = runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is Hysteria2ChildResult.Failed)
        assertFalse(runtime.isRunning())
        assertEquals(1, protect.stopCalls)
    }

    @Test
    fun `config file is written and deleted on stop, never left behind`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        val workDir = tempFolder.newFolder("work")

        runtime.start(config, "/fake/bin", workDir) { true }
        val configFile = File(workDir, "hysteria2-child-config.json")
        assertTrue("expected the config file to exist while running", configFile.exists())

        runtime.stop()
        assertFalse("expected the config file to be deleted on stop", configFile.exists())
    }

    @Test
    fun `repeated start while running is rejected`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        val second = runtime.start(config, "/fake/bin", tempFolder.newFolder("work2")) { true }

        assertTrue(second is Hysteria2ChildResult.Failed)
        assertEquals(1, launcher.launchCalls)
    }

    @Test
    fun `stop is idempotent`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        runtime.stop()
        runtime.stop()

        assertFalse(runtime.isRunning())
    }

    @Test
    fun `unexpected child exit notifies the owner exactly once and cleans up artifacts`() {
        val protect = FakeHysteria2ProtectBridge()
        val process = FakeHysteria2ChildProcess()
        val launcher = FakeHysteria2ChildProcessLauncher(process)
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        val notified = mutableListOf<Int>()
        runtime.onUnexpectedExit = { code -> notified.add(code) }
        val workDir = tempFolder.newFolder("work")
        runtime.start(config, "/fake/bin", workDir) { true }

        process.simulateUnexpectedExit(137)

        assertEquals(listOf(137), notified)
        assertFalse(runtime.isRunning())
        assertFalse(File(workDir, "hysteria2-child-config.json").exists())
    }

    @Test
    fun `stop after unexpected death is still idempotent and never double-notifies`() {
        val protect = FakeHysteria2ProtectBridge()
        val process = FakeHysteria2ChildProcess()
        val launcher = FakeHysteria2ChildProcessLauncher(process)
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        var notifiedCount = 0
        runtime.onUnexpectedExit = { notifiedCount++ }
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        process.simulateUnexpectedExit(137)
        assertEquals(1, notifiedCount)

        val stopResult = runtime.stop()

        assertTrue(stopResult is Hysteria2ChildResult.Ok)
        assertEquals(1, notifiedCount)
    }

    @Test
    fun `protector callback is forwarded from the protect bridge`() {
        var receivedFd = -1
        val protect = object : Hysteria2ProtectBridge {
            override fun start(socketPath: File, protector: (fd: Int) -> Boolean) {
                receivedFd = if (protector(42)) 42 else -1
            }
            override fun stop() {}
        }
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)

        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { fd -> fd == 42 }

        assertEquals(42, receivedFd)
    }

    @Test
    fun `production hard gate refuses insecure TLS and never launches the child`() {
        val protect = FakeHysteria2ProtectBridge()
        val launcher = FakeHysteria2ChildProcessLauncher()
        val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)
        val insecureConfig = config.copy(insecure = true)

        val result = runtime.start(insecureConfig, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is Hysteria2ChildResult.Failed)
        assertEquals(0, launcher.launchCalls)
        assertEquals(0, protect.startCalls)
        assertFalse(runtime.isRunning())
    }

    // --- B46-4A: local SOCKS hardening ---------------------------------------

    @Test
    fun `B46-4A the actually bound ephemeral socks address is parsed - no fixed port assumed`() {
        val launcher = FakeHysteria2ChildProcessLauncher(readyLineOnLaunch = "2026/10/02 12:00:00 SOCKS5_LISTENING addr=127.0.0.1:43999 auth=required")
        val runtime = Hysteria2ChildRuntime(launcher, FakeHysteria2ProtectBridge(), readyTimeoutMillis = 2_000)

        val result = runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }

        assertTrue(result is Hysteria2ChildResult.Ok)
        assertEquals("127.0.0.1:43999", runtime.boundSocksAddress)
    }

    @Test
    fun `B46-4A an invalid SOCKS5_LISTENING address fails closed and cleans up`() {
        for (line in listOf("SOCKS5_LISTENING addr=0.0.0.0:43999 auth=required", "SOCKS5_LISTENING addr=127.0.0.1:0 auth=required", "SOCKS5_LISTENING addr=[::1]:43999 auth=required", "SOCKS5_LISTENING auth=required")) {
            val process = FakeHysteria2ChildProcess()
            val protect = FakeHysteria2ProtectBridge()
            val runtime = Hysteria2ChildRuntime(FakeHysteria2ChildProcessLauncher(process, line), protect, readyTimeoutMillis = 2_000)
            val workDir = tempFolder.newFolder()

            val result = runtime.start(config, "/fake/bin", workDir) { true }

            assertTrue(line, result is Hysteria2ChildResult.Failed)
            assertFalse(line, runtime.isRunning())
            assertTrue(line, process.requestStopCalls > 0 || !process.alive)
            assertEquals(line, 1, protect.stopCalls)
            assertEquals(line, null, runtime.boundSocksAddress)
            assertFalse(line, File(workDir, "hysteria2-child-config.json").exists())
        }
    }

    @Test
    fun `B46-4A a pre-hardening child without the auth=required marker is refused`() {
        val process = FakeHysteria2ChildProcess()
        val protect = FakeHysteria2ProtectBridge()
        val runtime = Hysteria2ChildRuntime(FakeHysteria2ChildProcessLauncher(process, "SOCKS5_LISTENING addr=127.0.0.1:41080"), protect, readyTimeoutMillis = 2_000)
        val workDir = tempFolder.newFolder()

        val result = runtime.start(config, "/fake/bin", workDir) { true }

        assertTrue(result is Hysteria2ChildResult.Failed)
        assertFalse(runtime.isRunning())
        assertEquals(1, protect.stopCalls)
        assertFalse(File(workDir, "hysteria2-child-config.json").exists())
    }

    @Test
    fun `B46-4A missing local socks credentials fail closed before launch`() {
        for (bad in listOf(config.copy(socksUsername = ""), config.copy(socksPassword = ""))) {
            val launcher = FakeHysteria2ChildProcessLauncher()
            val protect = FakeHysteria2ProtectBridge()
            val runtime = Hysteria2ChildRuntime(launcher, protect, readyTimeoutMillis = 2_000)

            val result = runtime.start(bad, "/fake/bin", tempFolder.newFolder()) { true }

            assertTrue(result is Hysteria2ChildResult.Failed)
            assertEquals(0, launcher.launchCalls)
            assertEquals(0, protect.startCalls)
        }
    }

    @Test
    fun `B46-4A a non-loopback socks listen address fails closed before launch`() {
        for (listen in listOf("0.0.0.0:0", "0.0.0.0:41080", "192.168.1.5:0", "[::1]:0", "localhost:0", "127.0.0.1:99999")) {
            val launcher = FakeHysteria2ChildProcessLauncher()
            val runtime = Hysteria2ChildRuntime(launcher, FakeHysteria2ProtectBridge(), readyTimeoutMillis = 2_000)

            val result = runtime.start(config.copy(socksListen = listen), "/fake/bin", tempFolder.newFolder()) { true }

            assertTrue(listen, result is Hysteria2ChildResult.Failed)
            assertEquals(listen, 0, launcher.launchCalls)
        }
    }

    @Test
    fun `B46-4A config carries the per-session credentials only while running`() {
        val runtime = Hysteria2ChildRuntime(FakeHysteria2ChildProcessLauncher(), FakeHysteria2ProtectBridge(), readyTimeoutMillis = 2_000)
        val workDir = tempFolder.newFolder("work")
        runtime.start(config, "/fake/bin", workDir) { true }
        val configFile = File(workDir, "hysteria2-child-config.json")

        val json = org.json.JSONObject(configFile.readText())
        assertEquals("test-socks-user", json.getString("socksUsername"))
        assertEquals("test-socks-pass", json.getString("socksPassword"))
        assertEquals("127.0.0.1:0", json.getString("socksListen"))

        runtime.stop()
        assertFalse(configFile.exists())
        assertEquals(null, runtime.boundSocksAddress)
    }

    @Test
    fun `B46-4A child death clears the bound socks address`() {
        val process = FakeHysteria2ChildProcess()
        val runtime = Hysteria2ChildRuntime(FakeHysteria2ChildProcessLauncher(process), FakeHysteria2ProtectBridge(), readyTimeoutMillis = 2_000)
        runtime.start(config, "/fake/bin", tempFolder.newFolder("work")) { true }
        assertEquals("127.0.0.1:41080", runtime.boundSocksAddress)

        process.simulateUnexpectedExit(1)

        assertEquals(null, runtime.boundSocksAddress)
    }

    @Test
    fun `B46-4A config toString never contains secrets`() {
        val text = config.toString()
        for (secret in listOf("test-auth", "test-socks-user", "test-socks-pass")) {
            assertFalse(secret, text.contains(secret))
        }
    }
}
