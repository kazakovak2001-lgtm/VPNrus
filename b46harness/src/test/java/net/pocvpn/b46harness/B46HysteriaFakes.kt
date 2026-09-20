package net.pocvpn.b46harness

import java.io.File

internal class FakeB46HysteriaSpawnedProcess(
    override val pid: Int? = 1234,
    private var alive: Boolean = true,
) : B46HysteriaSpawnedProcess {
    var stopRequested = false
        private set
    var forceStopped = false
        private set
    private var exitCallback: ((Int) -> Unit)? = null
    private var logCallback: ((String) -> Unit)? = null
    private var pendingExitCode: Int? = null

    override fun isAlive(): Boolean = alive

    override fun requestStop() {
        stopRequested = true
    }

    override fun forceStop() {
        forceStopped = true
        alive = false
    }

    override fun waitForExit(timeoutMillis: Long): Int? = if (!alive) (pendingExitCode ?: 0) else null

    override fun onExit(callback: (Int) -> Unit) {
        exitCallback = callback
        val code = pendingExitCode
        if (!alive && code != null) callback(code)
    }

    override fun onLogLine(callback: (String) -> Unit) {
        logCallback = callback
    }

    /** Test-only: simulates the process exiting on its own (crash, upstream error). */
    fun simulateUnexpectedExit(exitCode: Int) {
        alive = false
        pendingExitCode = exitCode
        exitCallback?.invoke(exitCode)
    }

    /** Test-only: simulates one line the real child would print. */
    fun simulateLogLine(line: String) {
        logCallback?.invoke(line)
    }
}

internal class FakeB46HysteriaProcessLauncher(
    private val processFactory: () -> FakeB46HysteriaSpawnedProcess = { FakeB46HysteriaSpawnedProcess() },
    private val shouldFailToLaunch: Boolean = false,
) : B46HysteriaProcessLauncher {
    var lastBinaryPath: String? = null
        private set
    var lastArgs: List<String>? = null
        private set
    var launchCount = 0
        private set
    var lastLaunched: FakeB46HysteriaSpawnedProcess? = null
        private set

    override fun launch(binaryPath: String, args: List<String>, workingDir: File): B46HysteriaSpawnedProcess {
        launchCount++
        if (shouldFailToLaunch) throw java.io.IOException("simulated spawn failure")
        lastBinaryPath = binaryPath
        lastArgs = args
        val process = processFactory()
        lastLaunched = process
        return process
    }
}

internal class FakeB46HysteriaVpnProtectBridge : B46HysteriaVpnProtectBridge {
    var startCalls = 0
        private set
    var stopCalls = 0
        private set
    override var state: B46HysteriaProtectBridgeState = B46HysteriaProtectBridgeState.WAITING
        private set
    override var requestCount: Int = 0
        private set
    override var failureCount: Int = 0
        private set

    var throwOnStart = false
    private var lastProtector: B46HysteriaVpnProtector? = null

    override fun start(socketPath: File, protector: B46HysteriaVpnProtector) {
        startCalls++
        if (throwOnStart) throw java.io.IOException("simulated protect listener bind failure")
        lastProtector = protector
        state = B46HysteriaProtectBridgeState.RUNNING
    }

    override fun stop() {
        stopCalls++
        state = B46HysteriaProtectBridgeState.CLOSED
    }

    /** Test-only: simulates one child protect request end to end, exactly as [RealB46HysteriaVpnProtectBridge] would. */
    fun simulateRequest(fd: Int): Boolean {
        val protector = lastProtector ?: error("start() was never called")
        val succeeded = protector.protect(fd)
        requestCount++
        if (!succeeded) failureCount++
        return succeeded
    }
}

internal class FakeB46HysteriaVpnProtector(private val result: Boolean = true) : B46HysteriaVpnProtector {
    var callCount = 0
        private set
    var lastFd: Int? = null
        private set

    override fun protect(fd: Int): Boolean {
        callCount++
        lastFd = fd
        return result
    }
}

internal class FakeB46Tun2SocksBridge(
    private var startResult: B46Tun2SocksResult = B46Tun2SocksResult.Ok,
    private var stopResult: B46Tun2SocksResult = B46Tun2SocksResult.Ok,
) : B46Tun2SocksBridge {
    var startCalls = 0
        private set
    var stopCalls = 0
        private set
    var lastFd: Int? = null
        private set
    var lastMtu: Int? = null
        private set
    var lastSocksAddr: String? = null
        private set

    override fun start(fd: Int, mtu: Int, socksAddr: String): B46Tun2SocksResult {
        startCalls++
        lastFd = fd
        lastMtu = mtu
        lastSocksAddr = socksAddr
        return startResult
    }

    override fun stop(): B46Tun2SocksResult {
        stopCalls++
        return stopResult
    }
}

internal fun testConfig(protectPath: String = "") = B46HysteriaChildConfig(
    server = "203.0.113.1:34443",
    auth = "test-secret-auth-value",
    sni = "example.test",
    insecure = true,
    obfsSalamander = "",
    socksListen = "127.0.0.1:41080",
    protectPath = protectPath,
)
