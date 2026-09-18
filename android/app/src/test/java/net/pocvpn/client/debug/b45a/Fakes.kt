package net.pocvpn.client.debug.b45a

import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** B45A test fakes - SPIKE ONLY, never referenced from production code. */

class FakeB45ASpawnedProcess(
    override val pid: Int? = 1234,
    private var alive: Boolean = true,
) : B45ASpawnedProcess {
    var stopRequested = false
        private set
    var forceStopped = false
        private set
    private var exitCallback: ((Int) -> Unit)? = null
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

    /** Test-only: simulates the process exiting on its own (crash, upstream error). */
    fun simulateUnexpectedExit(exitCode: Int) {
        alive = false
        pendingExitCode = exitCode
        exitCallback?.invoke(exitCode)
    }
}

class FakeB45AProcessLauncher(
    private val processFactory: () -> FakeB45ASpawnedProcess = { FakeB45ASpawnedProcess() },
    private val shouldFailToLaunch: Boolean = false,
) : B45AProcessLauncher {
    var lastBinaryPath: String? = null
        private set
    var lastArgs: List<String>? = null
        private set
    var launchCount = 0
        private set
    var lastLaunched: FakeB45ASpawnedProcess? = null
        private set

    override fun launch(binaryPath: String, args: List<String>, workingDir: File): B45ASpawnedProcess {
        launchCount++
        if (shouldFailToLaunch) throw java.io.IOException("simulated spawn failure")
        lastBinaryPath = binaryPath
        lastArgs = args
        val process = processFactory()
        lastLaunched = process
        return process
    }
}

class FakeB45ATunFdBridge(private val result: B45ATunFdBridgeState = B45ATunFdBridgeState.FD_SENT) : B45ATunFdBridge {
    var handOffCalls = 0
        private set
    val latch = CountDownLatch(1)

    override fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): B45ATunFdBridgeState {
        handOffCalls++
        latch.countDown()
        return result
    }

    fun awaitCalled(timeoutMillis: Long = 2000) {
        latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }
}

class FakeB45AVpnProtectBridge : B45AVpnProtectBridge {
    var startCalls = 0
        private set
    var stopCalls = 0
        private set
    override var state: B45AProtectBridgeState = B45AProtectBridgeState.WAITING
        private set
    override var requestCount: Int = 0
    override var failureCount: Int = 0

    var throwOnStart: Boolean = false

    override fun start(socketPath: File, protector: B45AVpnProtector) {
        startCalls++
        if (throwOnStart) throw java.io.IOException("simulated protect listener bind failure")
        state = B45AProtectBridgeState.WAITING
    }

    override fun stop() {
        stopCalls++
        state = B45AProtectBridgeState.CLOSED
    }

    /** Test-only: simulates handling one protect request end to end. */
    fun simulateRequest(protector: B45AVpnProtector, fd: Int): Boolean {
        val succeeded = protector.protect(fd)
        requestCount++
        if (!succeeded) failureCount++
        state = if (succeeded) B45AProtectBridgeState.ACKNOWLEDGED else B45AProtectBridgeState.FAILED
        return succeeded
    }
}

class FakeB45AVpnProtector(private val result: Boolean = true) : B45AVpnProtector {
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
