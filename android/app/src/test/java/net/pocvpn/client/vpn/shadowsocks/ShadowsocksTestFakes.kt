package net.pocvpn.client.vpn.shadowsocks

import java.io.File

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

    override fun handOff(tunFd: Int, socketPath: File, timeoutMillis: Long): ShadowsocksTunFdBridgeState {
        handOffCalls++
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
