@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import android.content.Context
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.FakeAesGcmKeyEncryptor
import net.pocvpn.client.identity.FileXrayProfileStore
import net.pocvpn.client.identity.SecureXrayProfileRepository
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/**
 * B33 relay follow-up (round 3) - proves the post-Connected relay-health
 * watchdog fix for the physically-proven "stale Protected" defect: a
 * genuinely healthy CHAIN_DIRECT session whose relay-upstream link was then
 * black-holed stayed reported Connected for 6+ minutes with a dead data
 * plane, tun0 still up, Xray still running (see
 * [XrayCoreController.startRelayHealthWatchdog]'s own docs for the full root
 * cause). All tests run on a [kotlinx.coroutines.test.TestScope]'s virtual
 * time - the SAME "probeScope must be the calling test's own TestScope"
 * discipline [NovaXrayServiceLifecycleCoordinatorTest] already established -
 * so [XrayCoreController.RELAY_HEALTH_PROBE_INTERVAL_MS] is advanced
 * deterministically rather than waiting on it for real.
 */
class XrayCoreControllerRelayHealthWatchdogTest {

    private val validProfile = XrayProfile(
        server = "16.170.208.231",
        serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision",
        serverName = "www.microsoft.com",
        fingerprint = "chrome",
        realityPublicKey = "A".repeat(43),
        shortId = "a1b2c3d4",
    )

    private val exitProbeHost = "152.70.43.1"

    private fun newRepository(): SecureXrayProfileRepository =
        SecureXrayProfileRepository(FileXrayProfileStore(Files.createTempDirectory("relay-watchdog-test").toFile()), FakeAesGcmKeyEncryptor())

    /**
     * Unlike [FakeXrayCoreRuntime] (fixed behavior for the whole test),
     * [measureDelayResults] is a mutable queue consumed front-to-back by
     * successive `measureDelay` calls (the initial pre-Started confirmation
     * AND every later watchdog probe both go through it) - empty means
     * "healthy" (matches [FakeXrayCoreRuntime]'s own "succeeds by default"
     * discipline). Also tracks concurrent-call depth so a test can prove the
     * watchdog never overlaps two probes.
     */
    private class QueuedXrayCoreRuntime : XrayCoreRuntime {
        var startLoopCallCount = 0
            private set
        var stopLoopCallCount = 0
            private set
        var measureDelayCallCount = 0
            private set
        var lastMeasureDelayUrl: String? = null
            private set
        var maxConcurrentMeasureDelay = 0
            private set
        private var inFlight = 0
        private val measureDelayResults = ArrayDeque<Boolean>()

        fun enqueue(ok: Boolean) {
            measureDelayResults.addLast(ok)
        }

        override fun ensureCoreEnvInitialized(context: Context) {}
        override val isRunning: Boolean get() = startLoopCallCount > stopLoopCallCount
        override fun startLoop(configContent: String, tunFd: Int) {
            startLoopCallCount++
        }
        override fun stopLoop() {
            stopLoopCallCount++
        }
        override fun measureDelay(url: String): Long {
            inFlight++
            maxConcurrentMeasureDelay = maxOf(maxConcurrentMeasureDelay, inFlight)
            measureDelayCallCount++
            lastMeasureDelayUrl = url
            val ok = if (measureDelayResults.isEmpty()) true else measureDelayResults.removeFirst()
            inFlight--
            if (!ok) throw java.io.IOException("simulated relay probe failure")
            return 1L
        }
    }

    private class Harness(
        val runtime: QueuedXrayCoreRuntime,
        probeScope: kotlinx.coroutines.CoroutineScope,
        repository: SecureXrayProfileRepository,
    ) {
        var closeTunCallCount = 0
            private set

        val controller = XrayCoreController(
            repository = repository,
            coreRuntime = runtime,
            novaPackageId = "net.pocvpn.client.test",
            ensureCoreEnvInitialized = {},
            establishTun = { 42 },
            closeTun = { closeTunCallCount++ },
            probeScope = probeScope,
        )
    }

    private val endpointId = EndpointId("stockholm-ingress-1")

    @Test
    fun `healthy Relayed session - watchdog probes and remains Connected`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        val harness = Harness(runtime, probeScope = this, repository = repository)
        var unhealthyCalls = 0

        val outcome = harness.controller.requestStart(
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
            onRelayHealthLost = { unhealthyCalls++ },
        )
        assertEquals(XrayCoreStartOutcome.Started, outcome)

        // Advance past several probe intervals - every probe defaults to
        // healthy (queue stays empty).
        repeat(5) {
            advanceTimeBy(20_000L)
            runCurrent()
        }

        assertEquals(0, runtime.stopLoopCallCount)
        assertEquals(0, unhealthyCalls)
        assertTrue("expected repeated probes, got ${runtime.measureDelayCallCount}", runtime.measureDelayCallCount >= 5)
        assertEquals("https://$exitProbeHost/v1/manifest", runtime.lastMeasureDelayUrl)

        harness.controller.requestStop()
    }

    @Test
    fun `one transient probe failure does not tear down - remains Connected`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        runtime.enqueue(true) // initial pre-Started confirmation
        runtime.enqueue(false) // first watchdog probe: transient miss
        runtime.enqueue(true) // second watchdog probe: recovered
        val harness = Harness(runtime, probeScope = this, repository = repository)
        var unhealthyCalls = 0

        harness.controller.requestStart(
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
            onRelayHealthLost = { unhealthyCalls++ },
        )

        advanceTimeBy(20_000L); runCurrent() // consumes the transient miss
        assertEquals(0, runtime.stopLoopCallCount)
        advanceTimeBy(20_000L); runCurrent() // consumes the recovery
        assertEquals(0, runtime.stopLoopCallCount)
        assertEquals(0, unhealthyCalls)

        harness.controller.requestStop()
    }

    @Test
    fun `threshold consecutive failures tears down the exact session and releases the tun - UI leaves Connected`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        runtime.enqueue(true) // initial pre-Started confirmation
        runtime.enqueue(false) // watchdog probe 1: fail
        runtime.enqueue(false) // watchdog probe 2: fail - threshold (2) reached
        val harness = Harness(runtime, probeScope = this, repository = repository)
        var unhealthyCalls = 0

        harness.controller.requestStart(
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
            onRelayHealthLost = { unhealthyCalls++ },
        )

        advanceTimeBy(20_000L); runCurrent()
        assertEquals("one miss must not yet tear down", 0, runtime.stopLoopCallCount)
        advanceTimeBy(20_000L); runCurrent()

        // Requirement 3/4: the exact active relay session's Xray loop is
        // stopped exactly once.
        assertEquals(1, runtime.stopLoopCallCount)
        // Requirement 5: tun ownership is released.
        assertEquals(1, harness.closeTunCallCount)
        // Caller is notified AFTER teardown already completed (see
        // startRelayHealthWatchdog's own docs) - this is what lets
        // NovaXrayVpnService publish a terminal event knowing the tun/core
        // are already gone, never before.
        assertEquals(1, unhealthyCalls)

        // No stale watchdog left running against the now-dead session.
        val callsBeforeMoreTime = runtime.measureDelayCallCount
        advanceTimeBy(60_000L); runCurrent()
        assertEquals("watchdog must not keep polling after its own teardown", callsBeforeMoreTime, runtime.measureDelayCallCount)
    }

    @Test
    fun `disconnect (requestStop) cancels the watchdog - no further probes`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        val harness = Harness(runtime, probeScope = this, repository = repository)

        harness.controller.requestStart(confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost))
        advanceTimeBy(20_000L); runCurrent()
        val callsBeforeStop = runtime.measureDelayCallCount
        assertTrue(callsBeforeStop >= 1)

        harness.controller.requestStop()
        assertEquals(1, runtime.stopLoopCallCount)

        advanceTimeBy(120_000L); runCurrent()
        assertEquals("no probe after explicit disconnect", callsBeforeStop, runtime.measureDelayCallCount)
    }

    @Test
    fun `an old session's watchdog cannot affect a fresh new session`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtimeA = QueuedXrayCoreRuntime()
        val harnessA = Harness(runtimeA, probeScope = this, repository = repository)
        var unhealthyCallsA = 0
        harnessA.controller.requestStart(
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
            onRelayHealthLost = { unhealthyCallsA++ },
        )
        advanceTimeBy(20_000L); runCurrent()

        // Session A ends cleanly (never reached the failure threshold).
        harnessA.controller.requestStop()

        // A genuinely fresh session (own controller instance, own runtime,
        // own consecutive-failure counter) starts later - A's own watchdog
        // must be fully inert by now (see previous test) and must never
        // reach into B's outcome.
        val runtimeB = QueuedXrayCoreRuntime()
        runtimeB.enqueue(true) // B's own initial confirmation
        runtimeB.enqueue(false) // B's first probe - if A's stale state leaked in as an existing failure count, B would need only ONE more to hit threshold=2; prove it does not
        val harnessB = Harness(runtimeB, probeScope = this, repository = repository)
        var unhealthyCallsB = 0
        harnessB.controller.requestStart(
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
            onRelayHealthLost = { unhealthyCallsB++ },
        )
        advanceTimeBy(20_000L); runCurrent()

        assertEquals("A's own callback must never fire again after its clean stop", 0, unhealthyCallsA)
        assertEquals("B's single transient miss (its own FIRST) must not be treated as already at threshold", 0, unhealthyCallsB)
        assertEquals(0, runtimeB.stopLoopCallCount)

        harnessB.controller.requestStop()
    }

    @Test
    fun `Direct sessions never start a relay-health watchdog`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        val harness = Harness(runtime, probeScope = this, repository = repository)

        val outcome = harness.controller.requestStart(confirmationContext = RemoteConfirmationContext.Direct)
        assertEquals(XrayCoreStartOutcome.Started, outcome)
        val callsRightAfterStart = runtime.measureDelayCallCount

        advanceTimeBy(120_000L); runCurrent()

        assertEquals("no periodic probing for a Direct session", callsRightAfterStart, runtime.measureDelayCallCount)
        harness.controller.requestStop()
    }

    @Test
    fun `probes never overlap - at most one measureDelay call in flight at a time`() = runTest {
        val repository = newRepository()
        repository.saveProfile(validProfile)
        val runtime = QueuedXrayCoreRuntime()
        val harness = Harness(runtime, probeScope = this, repository = repository)

        harness.controller.requestStart(confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost))
        repeat(10) {
            advanceTimeBy(20_000L)
            runCurrent()
        }

        assertEquals(1, runtime.maxConcurrentMeasureDelay)
        harness.controller.requestStop()
    }

    @Test
    fun `switching endpoints via the lifecycle coordinator cancels the old endpoint's watchdog`() = runTest {
        val repositoryA = newRepository()
        repositoryA.saveProfile(validProfile)
        val repositoryB = newRepository()
        repositoryB.saveProfile(validProfile)
        val runtimeA = QueuedXrayCoreRuntime()
        val runtimeB = QueuedXrayCoreRuntime()
        val testScope = this
        val coordinator = NovaXrayServiceLifecycleCoordinator { endpointId ->
            if (endpointId.value == "endpoint-a") {
                XrayCoreController(
                    repository = repositoryA, coreRuntime = runtimeA, novaPackageId = "net.pocvpn.client.test",
                    ensureCoreEnvInitialized = {}, establishTun = { 42 }, closeTun = {}, probeScope = testScope,
                )
            } else {
                XrayCoreController(
                    repository = repositoryB, coreRuntime = runtimeB, novaPackageId = "net.pocvpn.client.test",
                    ensureCoreEnvInitialized = {}, establishTun = { 42 }, closeTun = {}, probeScope = testScope,
                )
            }
        }

        coordinator.start(
            EndpointId("endpoint-a"), TransportKind.XRAY_REALITY,
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
        )
        advanceTimeBy(20_000L); runCurrent()
        val callsToABeforeSwitch = runtimeA.measureDelayCallCount
        assertTrue(callsToABeforeSwitch >= 1)

        // A genuinely DIFFERENT endpoint - selectControllerLocked tears down
        // A's controller (requestStop(), which cancels its watchdog) before
        // B is ever built (see that function's own docs).
        coordinator.start(
            EndpointId("endpoint-b"), TransportKind.XRAY_REALITY,
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = exitProbeHost),
        )
        assertEquals(1, runtimeA.stopLoopCallCount)

        advanceTimeBy(60_000L); runCurrent()
        assertEquals("A's watchdog must not still be probing after the endpoint switch", callsToABeforeSwitch, runtimeA.measureDelayCallCount)

        coordinator.stop()
    }
}
