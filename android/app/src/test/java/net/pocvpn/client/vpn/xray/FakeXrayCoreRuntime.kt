package net.pocvpn.client.vpn.xray

import android.content.Context

/**
 * B8K4C - JVM test double for [XrayCoreRuntime]. Never touches a real native
 * .so - just counts calls and records the LAST startLoop's arguments so
 * tests can assert the exact renderedConfig/fd reached it, and can force
 * startLoop to throw to exercise [XrayCoreController]'s failure path.
 */
class FakeXrayCoreRuntime(private val startLoopThrows: Throwable? = null) : XrayCoreRuntime {

    var ensureCoreEnvInitializedCallCount = 0
        private set
    var startLoopCallCount = 0
        private set
    var stopLoopCallCount = 0
        private set
    var lastStartedConfigContent: String? = null
        private set
    var lastStartedTunFd: Int? = null
        private set

    override fun ensureCoreEnvInitialized(context: Context) {
        ensureCoreEnvInitializedCallCount++
    }

    override val isRunning: Boolean
        get() = startLoopCallCount > stopLoopCallCount

    override fun startLoop(configContent: String, tunFd: Int) {
        startLoopCallCount++
        startLoopThrows?.let { throw it }
        lastStartedConfigContent = configContent
        lastStartedTunFd = tunFd
    }

    override fun stopLoop() {
        stopLoopCallCount++
    }
}
