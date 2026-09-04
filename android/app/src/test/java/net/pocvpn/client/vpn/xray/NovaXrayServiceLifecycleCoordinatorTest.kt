@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.xray

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import net.pocvpn.client.identity.XrayProfile
import net.pocvpn.client.identity.XrayProfileRepository
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B13 (2026-08-30 PR #25 review fix) - proves NovaXrayServiceLifecycleCoordinator
 * actually serializes controller selection + start/stop against REAL
 * coroutine interleaving (not asserted from a "single-threaded Binder path"
 * assumption - that assumption was the confirmed bug this class fixes).
 * Uses a real [XrayCoreController] per endpoint (same fakes
 * [XrayCoreControllerTest] already uses) with a controllable suspension
 * point in the profile repository read, so a test can force two coordinator
 * calls to genuinely overlap and prove only one lifecycle authority ever
 * wins.
 */
class NovaXrayServiceLifecycleCoordinatorTest {

    private val validProfile = XrayProfile(
        server = "152.70.43.1", serverPort = 443,
        uuid = "3f29c1a4-6b8e-4d2a-9c3e-7a1b2c3d4e5f",
        flow = "xtls-rprx-vision", serverName = "www.microsoft.com",
        fingerprint = "chrome", realityPublicKey = "A".repeat(43), shortId = "a1b2c3d4",
    )

    /** Suspends on [gate] (if provided) before returning the profile - the controllable interleaving point every test below uses. */
    private class GatedXrayProfileRepository(
        private val profile: XrayProfile?,
        private val gate: CompletableDeferred<Unit>? = null,
    ) : XrayProfileRepository {
        override suspend fun getProfileOrNull(): XrayProfile? {
            gate?.await()
            return profile
        }
        override suspend fun saveProfile(profile: XrayProfile) {}
        override suspend fun clearProfile() {}
    }

    // B33 review fix (round 2) - [probeScope] MUST be the calling test's own
    // TestScope (never the real Dispatchers.IO-backed default
    // XrayCoreController itself falls back to in production): the bounded
    // remote-confirmation probe this class now runs on its own coroutine
    // (see XrayCoreController.confirmRemoteConnectivity's own docs) would
    // otherwise race kotlinx-coroutines-test's virtual scheduler exactly
    // like the ORIGINAL (naive withTimeoutOrNull-only) version already did
    // once before - runCurrent()/the test's own assertions have no way to
    // wait for a REAL background thread's completion. Every FakeXrayCoreRuntime
    // used in this file returns from measureDelay() synchronously/instantly,
    // so running the probe on the SAME virtual test dispatcher is both
    // correct and deterministic here.
    private fun buildController(
        gate: CompletableDeferred<Unit>? = null,
        runtime: FakeXrayCoreRuntime = FakeXrayCoreRuntime(),
        probeScope: kotlinx.coroutines.CoroutineScope,
    ): XrayCoreController =
        XrayCoreController(
            repository = GatedXrayProfileRepository(validProfile, gate),
            coreRuntime = runtime,
            novaPackageId = "net.pocvpn.client.test",
            ensureCoreEnvInitialized = {},
            establishTun = { 42 },
            closeTun = {},
            probeScope = probeScope,
        )

    private val endpointA = EndpointId("gateway-a")
    private val endpointB = EndpointId("gateway-b")

    @Test
    fun `simultaneous START(A) plus START(A) - exactly one controller, one start authority`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val runtime = FakeXrayCoreRuntime()
        var factoryCallCount = 0
        val coordinator = NovaXrayServiceLifecycleCoordinator {
            factoryCallCount++
            buildController(gate, runtime, probeScope = this)
        }

        val first = async { coordinator.start(endpointA, TransportKind.XRAY_REALITY) }
        runCurrent()
        // `first` is now suspended mid-flight (blocked on the repository
        // gate) - it holds the coordinator's mutex the whole time.
        val second = async { coordinator.start(endpointA, TransportKind.XRAY_REALITY) }
        runCurrent()

        // `second` must not have progressed past the mutex at all yet - only
        // ONE controller was ever built, and startLoop was never called by it.
        assertEquals(1, factoryCallCount)
        assertEquals(0, runtime.startLoopCallCount)

        gate.complete(Unit)
        runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, first.await())
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, second.await())
        assertEquals(1, runtime.startLoopCallCount)
        assertEquals(1, factoryCallCount)
    }

    @Test
    fun `overlapping START(A) plus START(B) - serialized transition, never two active controllers`() = runTest {
        val gateA = CompletableDeferred<Unit>()
        val runtimeA = FakeXrayCoreRuntime()
        val runtimeB = FakeXrayCoreRuntime()
        val builtFor = mutableListOf<EndpointId>()
        val coordinator = NovaXrayServiceLifecycleCoordinator { endpointId ->
            builtFor += endpointId
            if (endpointId == endpointA) buildController(gateA, runtimeA, probeScope = this) else buildController(null, runtimeB, probeScope = this)
        }

        val startA = async { coordinator.start(endpointA, TransportKind.XRAY_REALITY) }
        runCurrent()
        // A is mid-flight (blocked on its own gate), holding the mutex.
        val startB = async { coordinator.start(endpointB, TransportKind.XRAY_REALITY) }
        runCurrent()

        // B must not have been built or started yet - still queued on the mutex.
        assertEquals(listOf(endpointA), builtFor)
        assertEquals(0, runtimeB.startLoopCallCount)

        gateA.complete(Unit)
        runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, startA.await())
        assertEquals(XrayCoreStartOutcome.Started, startB.await())
        // A was authoritatively torn down as part of the SAME serialized
        // transition, strictly before B's own controller was even built.
        assertEquals(1, runtimeA.startLoopCallCount)
        assertEquals(1, runtimeA.stopLoopCallCount)
        assertEquals(1, runtimeB.startLoopCallCount)
        assertEquals(0, runtimeB.stopLoopCallCount)
        assertEquals(listOf(endpointA, endpointB), builtFor)
    }

    @Test
    fun `stop racing an in-flight start is serialized, never lost, never races it`() = runTest {
        val gate = CompletableDeferred<Unit>()
        val runtime = FakeXrayCoreRuntime()
        val coordinator = NovaXrayServiceLifecycleCoordinator { buildController(gate, runtime, probeScope = this) }

        val start = async { coordinator.start(endpointA, TransportKind.XRAY_REALITY) }
        runCurrent()
        val stop = async { coordinator.stop() }
        runCurrent()

        // stop() must not have run yet - it is queued behind the in-flight start.
        assertEquals(0, runtime.stopLoopCallCount)

        gate.complete(Unit)
        runCurrent()

        assertEquals(XrayCoreStartOutcome.Started, start.await())
        val stopOutcome = stop.await()
        // Once it finally ran (strictly after start completed), stop correctly tore down what start left running.
        assertTrue(stopOutcome.didTeardown)
        assertEquals(1, runtime.stopLoopCallCount)
    }

    @Test
    fun `sequential repeated START(A) still preserves AlreadyRunning - one controller reused`() = runTest {
        val runtime = FakeXrayCoreRuntime()
        var factoryCallCount = 0
        val coordinator = NovaXrayServiceLifecycleCoordinator { factoryCallCount++; buildController(null, runtime, probeScope = this) }

        val first = coordinator.start(endpointA, TransportKind.XRAY_REALITY)
        val second = coordinator.start(endpointA, TransportKind.XRAY_REALITY)

        assertEquals(XrayCoreStartOutcome.Started, first)
        assertEquals(XrayCoreStartOutcome.AlreadyRunning, second)
        assertEquals(1, factoryCallCount)
        assertEquals(1, runtime.startLoopCallCount)
    }

    // --- B33 relay follow-up: confirmationContext threads through unchanged ---

    @Test
    fun `start with no confirmationContext argument still defaults to Direct - byte-for-byte unaffected`() = runTest {
        val runtime = FakeXrayCoreRuntime()
        val coordinator = NovaXrayServiceLifecycleCoordinator { buildController(null, runtime, probeScope = this) }

        val outcome = coordinator.start(endpointA, TransportKind.XRAY_REALITY)

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        assertEquals(1, runtime.measureDelayCallCount)
    }

    @Test
    fun `start with an explicit Relayed confirmationContext threads it through to the underlying controller`() = runTest {
        val runtime = FakeXrayCoreRuntime()
        val coordinator = NovaXrayServiceLifecycleCoordinator { buildController(null, runtime, probeScope = this) }

        val outcome = coordinator.start(
            endpointA,
            TransportKind.XRAY_REALITY,
            confirmationContext = RemoteConfirmationContext.Relayed(exitProbeHost = "203.0.113.60"),
        )

        assertEquals(XrayCoreStartOutcome.Started, outcome)
        // Dials the EXIT host's own manifest via the SAME Xray-native
        // measureDelay primitive Direct uses - see RemoteConfirmationContext
        // .Relayed's own docs.
        assertEquals(1, runtime.measureDelayCallCount)
        assertEquals("https://203.0.113.60/v1/manifest", runtime.lastMeasureDelayUrl)
    }

    @Test
    fun `stop with nothing ever started is a safe no-op`() = runTest {
        val coordinator = NovaXrayServiceLifecycleCoordinator { buildController(probeScope = this) }

        val outcome = coordinator.stop()

        assertEquals(XrayCoreStopOutcome(didTeardown = false), outcome)
    }

    @Test
    fun `a completed A to B switch never leaves A's controller as the cached one`() = runTest {
        val runtimesByEndpoint = mutableMapOf<EndpointId, MutableList<FakeXrayCoreRuntime>>()
        val coordinator = NovaXrayServiceLifecycleCoordinator { endpointId ->
            val runtime = FakeXrayCoreRuntime()
            runtimesByEndpoint.getOrPut(endpointId) { mutableListOf() } += runtime
            buildController(null, runtime, probeScope = this)
        }

        coordinator.start(endpointA, TransportKind.XRAY_REALITY)
        coordinator.start(endpointB, TransportKind.XRAY_REALITY)
        // A fresh start() for A again must build a THIRD (genuinely NEW)
        // controller instance - proving B, not A's original instance, was
        // the cached one - rather than reporting AlreadyRunning against A's
        // own now-stopped, orphaned instance.
        val restartA = coordinator.start(endpointA, TransportKind.XRAY_REALITY)

        assertEquals(XrayCoreStartOutcome.Started, restartA)
        assertEquals(2, runtimesByEndpoint.getValue(endpointA).size) // built twice: original + restart
        assertEquals(1, runtimesByEndpoint.getValue(endpointB).size)
        val (originalA, restartedA) = runtimesByEndpoint.getValue(endpointA)
        assertEquals(1, originalA.startLoopCallCount)
        assertEquals(1, originalA.stopLoopCallCount) // torn down when B started
        assertEquals(1, restartedA.startLoopCallCount) // the restart is a genuinely fresh session
        assertEquals(0, restartedA.stopLoopCallCount)
        val endpointBRuntime = runtimesByEndpoint.getValue(endpointB).single()
        assertEquals(1, endpointBRuntime.startLoopCallCount)
        assertEquals(1, endpointBRuntime.stopLoopCallCount) // torn down when A restarted
    }
}
