package net.pocvpn.client.vpn.xray

import android.content.Context
import kotlinx.coroutines.delay

/**
 * B8K4C - JVM test double for [XrayCoreRuntime]. Never touches a real native
 * .so - just counts calls and records the LAST startLoop's arguments so
 * tests can assert the exact renderedConfig/fd reached it, and can force
 * startLoop to throw to exercise [XrayCoreController]'s failure path.
 *
 * B21-fix - [measureDelayResult]/[measureDelayThrows]/[measureDelayDelayMs]
 * drive [XrayDataPlaneReadinessCheck]'s three outcomes: a default instant
 * success so every pre-existing test (which never mentions readiness at all)
 * keeps observing [XrayCoreStartOutcome.Started] unchanged, a thrown
 * exception for [XrayDataPlaneReadiness.Failed], and a [delay] longer than
 * the controller's own readiness timeout for [XrayDataPlaneReadiness.Timeout] -
 * a real suspend delay, not Thread.sleep, so it cooperates with
 * `withTimeoutOrNull` under `runBlocking` instead of blocking the test thread.
 */
class FakeXrayCoreRuntime(
    private val startLoopThrows: Throwable? = null,
    private val measureDelayResult: Long = 0L,
    private val measureDelayThrows: Throwable? = null,
    private val measureDelayDelayMs: Long = 0L,
) : XrayCoreRuntime {

    var ensureCoreEnvInitializedCallCount = 0
        private set
    var startLoopCallCount = 0
        private set
    var stopLoopCallCount = 0
        private set
    var measureDelayCallCount = 0
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

    override suspend fun measureDelay(testUrl: String): Long {
        measureDelayCallCount++
        if (measureDelayDelayMs > 0) delay(measureDelayDelayMs)
        measureDelayThrows?.let { throw it }
        return measureDelayResult
    }
}
