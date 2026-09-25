package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import java.io.FileDescriptor

internal class FakeShadowsocksSpawnedProcess : ShadowsocksSpawnedProcess {
    var stopRequested = false
        private set
    var forceStopped = false
        private set
    private var alive = true
    private var exitCallback: ((Int) -> Unit)? = null

    override fun isAlive(): Boolean = alive
    override fun requestStop() {
        stopRequested = true
    }
    override fun forceStop() {
        forceStopped = true
        alive = false
    }
    override fun waitForExit(timeoutMillis: Long): Int? = if (!alive) 0 else null
    override fun onExit(callback: (exitCode: Int) -> Unit) {
        exitCallback = callback
    }

    fun simulateUnexpectedExit(exitCode: Int) {
        alive = false
        exitCallback?.invoke(exitCode)
    }
}

internal class FakeShadowsocksProcessLauncher(
    private val shouldFailToLaunch: Boolean = false,
    private val processFactory: () -> FakeShadowsocksSpawnedProcess = { FakeShadowsocksSpawnedProcess() },
) : ShadowsocksProcessLauncher {
    var launchCount = 0
        private set
    var lastArgs: List<String>? = null
        private set
    var lastBinaryPath: String? = null
        private set

    override fun launch(binaryPath: String, args: List<String>, workingDir: File): ShadowsocksSpawnedProcess {
        launchCount++
        lastArgs = args
        lastBinaryPath = binaryPath
        if (shouldFailToLaunch) throw java.io.IOException("simulated launch failure")
        return processFactory()
    }
}

internal class FakeShadowsocksTunFdBridge(
    private val result: ShadowsocksTunFdBridgeState = ShadowsocksTunFdBridgeState.FD_SENT,
) : ShadowsocksTunFdBridge {
    var handOffCalls = 0
        private set

    /** Set whenever handOff is invoked - lets tests assert the EXACT same [FileDescriptor] instance the caller passed in was forwarded, never a copy/replacement. */
    var lastTunFd: FileDescriptor? = null
        private set

    override fun handOff(tunFd: FileDescriptor, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState {
        handOffCalls++
        lastTunFd = tunFd
        return result
    }
}

internal class FakeShadowsocksVpnProtectBridge(var throwOnStart: Boolean = false) : ShadowsocksVpnProtectBridge {
    var startCalls = 0
        private set
    var stopCalls = 0
        private set

    override var state: ShadowsocksProtectBridgeState = ShadowsocksProtectBridgeState.WAITING
        private set

    override fun start(socketPath: File, protector: ShadowsocksVpnProtector) {
        startCalls++
        if (throwOnStart) throw java.io.IOException("simulated bind failure")
        state = ShadowsocksProtectBridgeState.RUNNING
    }

    override fun stop() {
        stopCalls++
        state = ShadowsocksProtectBridgeState.CLOSED
    }
}

internal class FakeShadowsocksVpnProtector(private val result: Boolean = true) : ShadowsocksVpnProtector {
    override fun protect(fd: Int): Boolean = result
}

/**
 * Lifecycle race tests - every handOff call blocks until the test releases
 * that call's own [Gate]. This gives deterministic control over WHEN a
 * start()'s asynchronous completion runs relative to stop()/start(); it
 * never relies on timing. The await timeout only turns a test bug into a
 * failure instead of a hang.
 */
internal class GatedShadowsocksTunFdBridge : ShadowsocksTunFdBridge {
    class Gate {
        val reached = java.util.concurrent.CountDownLatch(1)
        private val released = java.util.concurrent.CountDownLatch(1)
        @Volatile private var result = ShadowsocksTunFdBridgeState.WAITING

        fun release(result: ShadowsocksTunFdBridgeState) {
            this.result = result
            released.countDown()
        }

        fun awaitReached() = check(reached.await(10, java.util.concurrent.TimeUnit.SECONDS)) { "handOff was never reached" }

        internal fun block(): ShadowsocksTunFdBridgeState {
            reached.countDown()
            check(released.await(10, java.util.concurrent.TimeUnit.SECONDS)) { "gate was never released" }
            return result
        }
    }

    private val gates = java.util.concurrent.ConcurrentHashMap<Int, Gate>()
    private val calls = java.util.concurrent.atomic.AtomicInteger(0)

    /** The gate of the [call]-th handOff (0-based), created on first use by either side. */
    fun gate(call: Int): Gate = gates.computeIfAbsent(call) { Gate() }

    override fun handOff(tunFd: FileDescriptor, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState =
        gate(calls.getAndIncrement()).block()
}
