@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.debug.b45a

import java.io.File
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Reuses the real [B45ATunNetworkConfig.CIDR] rather than an independent test literal - Phase 2's own anti-drift rule applies to tests too. */
private const val TEST_TUN_CIDR = B45ATunNetworkConfig.CIDR

/**
 * B45A - SPIKE ONLY. Unit tests for [B45ARuntime]'s pure state-machine
 * behavior against fakes - never a real process, never a real Android
 * socket. Covers the Phase 13 requirements this environment can actually
 * verify without a device (A, B, C, D, K, M, N below); the ones requiring a
 * real Android runtime (E/F/G/H/I/J/L/O) are explicitly NOT claimed here -
 * see docs/B45A_SHADOWSOCKS_RUST_SPIKE.md's own test-coverage section.
 */
class B45ARuntimeTest {

    private fun tempWorkingDir(): File = kotlin.io.path.createTempDirectory("b45a-test").toFile().apply { deleteOnExit() }

    private fun existingBinaryPath(): String {
        val f = kotlin.io.path.createTempFile("fake-sslocal", "").toFile()
        f.deleteOnExit()
        return f.absolutePath
    }

    // A. runtime state machine - basic start/stop transitions
    @Test
    fun `start transitions from STOPPED to RUNNING`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val tunFdBridge = FakeB45ATunFdBridge()
        val protectBridge = FakeB45AVpnProtectBridge()
        val protector = FakeB45AVpnProtector()
        val runtime = B45ARuntime(launcher, tunFdBridge, protectBridge, protector, this)

        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)

        val started = runtime.start(existingBinaryPath(), tunFd = 42, workingDir = tempWorkingDir(), tunInterfaceAddressCidr = TEST_TUN_CIDR)

        assertTrue(started)
        assertEquals(B45ARuntimePhase.RUNNING, runtime.status.value.phase)
        assertEquals(1, launcher.launchCount)
        assertEquals(1, protectBridge.startCalls)
    }

    // Round 5 - the args real sslocal receives must include the exact
    // Android-side TUN address/prefix, in the exact CIDR shape upstream's
    // own parser expects (see B45ATunNetworkConfigTest for the format
    // guard) - never omitted (round 4's own root cause) and never an
    // independently-drifted literal.
    @Test
    fun `start passes --tun-interface-address with the exact configured CIDR`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        val args = launcher.lastArgs
        assertTrue(args != null && args.contains("--tun-interface-address"))
        assertEquals(TEST_TUN_CIDR, args!![args.indexOf("--tun-interface-address") + 1])
    }

    // Section 34's own root-cause finding: local-tun's Mode defaults to
    // TcpOnly for every ProtocolType except Dns, so every UDP packet was
    // silently discarded before any Shadowsocks UDP encoding ever ran. `-U`
    // is the real sslocal CLI flag (upstream's own `TCP_AND_UDP` arg) that
    // sets Mode::TcpAndUdp - these tests guard the one-line fix that adds it.
    @Test
    fun `start passes -U to enable UDP relay alongside TCP`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        val args = launcher.lastArgs
        assertTrue("expected -U in sslocal args: $args", args != null && args.contains("-U"))
    }

    @Test
    fun `start does not pass -U more than once`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        val args = launcher.lastArgs!!
        assertEquals(1, args.count { it == "-U" })
    }

    @Test
    fun `start still passes the tun protocol, server, cipher, and vpn flags unchanged alongside -U`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        val args = launcher.lastArgs!!
        // TCP-relevant flags (protocol/server/cipher/key/vpn) are untouched -
        // -U is additive, not a replacement for any existing arg.
        assertTrue(args.contains("--protocol"))
        assertEquals("tun", args[args.indexOf("--protocol") + 1])
        assertTrue(args.contains("-s"))
        assertTrue(args.contains("-m"))
        assertTrue(args.contains("-k"))
        assertTrue(args.contains("--vpn"))
        assertTrue(args.contains("--tun-device-fd-from-path"))
    }

    // Round 6 (data-plane validation) - refreshProtectStatus() is a plain,
    // synchronous, idempotent pull (never a background loop inside
    // B45ARuntime itself - that broke runTest's completion invariant for
    // every test that doesn't call stop(), see B45ARuntime's own doc
    // comment on this) - real callers poll it themselves.
    @Test
    fun `refreshProtectStatus pulls the protect bridge's real counters into status while RUNNING`() = runTest {
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(FakeB45AProcessLauncher(), FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)
        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        protectBridge.simulateRequest(FakeB45AVpnProtector(result = true), fd = 7)
        runtime.refreshProtectStatus()

        assertEquals(1, runtime.status.value.protectRequestCount)
        assertEquals(0, runtime.status.value.protectFailureCount)
        assertEquals(B45AProtectBridgeState.ACKNOWLEDGED, runtime.status.value.protectBridgeState)
    }

    @Test
    fun `refreshProtectStatus is a no-op when not RUNNING`() {
        val runtime = B45ARuntime(
            FakeB45AProcessLauncher(), FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(),
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined),
        )

        runtime.refreshProtectStatus() // STOPPED - must not throw or change anything

        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)
    }

    // Round 5 (B45ASpikeTransitions.running fix) - protectBridgeState, set
    // before sslocal is spawned, must survive the transition to RUNNING,
    // not be silently reset by a fresh B45ASpikeStatus construction.
    @Test
    fun `protectBridgeState survives the transition to RUNNING`() = runTest {
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(FakeB45AProcessLauncher(), FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        assertEquals(B45ARuntimePhase.RUNNING, runtime.status.value.phase)
        assertEquals(B45AProtectBridgeState.WAITING, runtime.status.value.protectBridgeState)
    }

    // B. double-start rejected/deduplicated
    @Test
    fun `second start call while RUNNING is rejected`() = runTest {
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        val workingDir = tempWorkingDir()
        val binary = existingBinaryPath()
        assertTrue(runtime.start(binary, 1, workingDir, TEST_TUN_CIDR))
        val secondStart = runtime.start(binary, 2, workingDir, TEST_TUN_CIDR)

        assertFalse(secondStart)
        assertEquals(1, launcher.launchCount) // never a second real spawn
    }

    // C. stop is idempotent
    @Test
    fun `stop on an already-stopped runtime is a no-op`() {
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(
            FakeB45AProcessLauncher(),
            FakeB45ATunFdBridge(),
            protectBridge,
            FakeB45AVpnProtector(),
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined),
        )

        runtime.stop()
        runtime.stop()

        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)
        assertEquals(0, protectBridge.stopCalls) // never touched - nothing was ever started
    }

    // D. failed spawn cleans up
    @Test
    fun `failed spawn stops the protect bridge and transitions to FAILED`() = runTest {
        val launcher = FakeB45AProcessLauncher(shouldFailToLaunch = true)
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        val started = runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        assertFalse(started)
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B45ASpikeError.SpawnFailed)
        assertEquals(1, protectBridge.startCalls)
        assertEquals(1, protectBridge.stopCalls) // cleaned up, never left dangling
    }

    @Test
    fun `missing binary fails before touching the protect bridge`() = runTest {
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(FakeB45AProcessLauncher(), FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        val started = runtime.start("/does/not/exist/sslocal", 1, tempWorkingDir(), TEST_TUN_CIDR)

        assertFalse(started)
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B45ASpikeError.BinaryMissing)
        assertEquals(0, protectBridge.startCalls) // never started for a request that can't possibly succeed
    }

    @Test
    fun `protect listener failure fails the whole start attempt`() = runTest {
        val protectBridge = FakeB45AVpnProtectBridge().apply { throwOnStart = true }
        val launcher = FakeB45AProcessLauncher()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        val started = runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)

        assertFalse(started)
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B45ASpikeError.ProtectListenerFailed)
        assertEquals(0, launcher.launchCount) // never spawns sslocal if the protect listener can't even bind
    }

    // K. service stop closes listeners
    @Test
    fun `stop requests process termination and closes the protect bridge`() = runTest {
        val process = FakeB45ASpawnedProcess()
        val launcher = FakeB45AProcessLauncher(processFactory = { process })
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)
        runtime.stop()

        assertTrue(process.stopRequested)
        assertEquals(1, protectBridge.stopCalls)
        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)
    }

    @Test
    fun `stop force-kills a process that does not exit gracefully`() = runTest {
        val process = FakeB45ASpawnedProcess() // never reports exit via waitForExit -> forced path
        val launcher = FakeB45AProcessLauncher(processFactory = { process })
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)
        runtime.stop()

        assertTrue(process.stopRequested)
        assertTrue(process.forceStopped) // graceful path never reported exit -> forced cleanup, never a hang
    }

    // M. process exit clears runtime ownership
    @Test
    fun `unexpected process exit while RUNNING transitions to FAILED and stops the protect bridge`() = runTest {
        val process = FakeB45ASpawnedProcess()
        val launcher = FakeB45AProcessLauncher(processFactory = { process })
        val protectBridge = FakeB45AVpnProtectBridge()
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), protectBridge, FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)
        assertEquals(B45ARuntimePhase.RUNNING, runtime.status.value.phase)

        process.simulateUnexpectedExit(exitCode = 1)

        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertEquals(1, runtime.status.value.exitCode)
        assertEquals(1, protectBridge.stopCalls) // stopped by the crash handler - start() itself never stops it
    }

    @Test
    fun `unexpected exit after an explicit stop is not double-reported`() = runTest {
        val process = FakeB45ASpawnedProcess()
        val launcher = FakeB45AProcessLauncher(processFactory = { process })
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)
        process.forceStop() // simulates stop()'s own force-kill happening first
        runtime.stop()
        process.simulateUnexpectedExit(0) // the exit event finally arrives, after we already stopped cleanly

        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase) // never clobbered back to FAILED
    }

    // Successful fd-transfer protocol wiring (F, at the orchestration level - the real wire protocol is FakeB45ATunFdBridge's own contract, exercised for real only against a device, see RealB45ATunFdBridge's own docs)
    @Test
    fun `successful tun fd handoff is reflected in status`() = runTest {
        val tunFdBridge = FakeB45ATunFdBridge(result = B45ATunFdBridgeState.FD_SENT)
        val runtime = B45ARuntime(
            FakeB45AProcessLauncher(), tunFdBridge, FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), 99, tempWorkingDir(), TEST_TUN_CIDR)

        assertEquals(1, tunFdBridge.handOffCalls)
        assertEquals(B45ATunFdBridgeState.FD_SENT, runtime.status.value.tunFdBridgeState)
        assertEquals(B45ARuntimePhase.RUNNING, runtime.status.value.phase) // a successful handoff never demotes RUNNING
    }

    @Test
    fun `failed tun fd handoff transitions RUNNING to FAILED`() = runTest {
        val tunFdBridge = FakeB45ATunFdBridge(result = B45ATunFdBridgeState.FAILED)
        val runtime = B45ARuntime(
            FakeB45AProcessLauncher(), tunFdBridge, FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), 99, tempWorkingDir(), TEST_TUN_CIDR)

        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B45ASpikeError.TunFdHandoffTimedOut)
    }

    // G/H. protect success/failure at the bridge-orchestration level (the real wire protocol is RealB45AVpnProtectBridge's own contract - see its docs for why it cannot be exercised without a device)
    @Test
    fun `protect bridge records success and failure outcomes distinctly`() {
        val protectBridge = FakeB45AVpnProtectBridge()
        val succeedingProtector = FakeB45AVpnProtector(result = true)
        val failingProtector = FakeB45AVpnProtector(result = false)

        val succeeded = protectBridge.simulateRequest(succeedingProtector, fd = 7)
        assertTrue(succeeded)
        assertEquals(1, protectBridge.requestCount)
        assertEquals(0, protectBridge.failureCount)

        val failed = protectBridge.simulateRequest(failingProtector, fd = 8)
        assertFalse(failed)
        assertEquals(2, protectBridge.requestCount)
        assertEquals(1, protectBridge.failureCount)
    }

    // --- Physical-test-driven fixes (2026-09-18 narrow fix pass) ---
    //
    // The two physical-test defects were:
    //   (A) sslocal not resolvable at its expected path (nativeLibraryDir
    //       empty due to extractNativeLibs=false) - fixed in
    //       B45ASpikeVpnService (Android-only, asset extraction + chmod;
    //       not unit-testable without Robolectric/a device - see the doc's
    //       own disclosed test-coverage gap, and the physical re-test below).
    //   (B) Stop after a FAILED-before-runtime-existed start left the
    //       SERVICE's own status stuck FAILED - the underlying INVARIANT
    //       this bug violated ("any explicit Stop ends in STOPPED, whether
    //       or not a runtime/process/TUN ever existed") is exactly what
    //       B45ARuntime.stop()'s own idempotency already guarantees at ITS
    //       level (see `stop on an already-stopped runtime is a no-op`
    //       above) - these two tests extend that same guarantee to the
    //       "failed before ever starting anything real" and "start again
    //       after a fail-then-stop cycle" shapes specifically, which were
    //       not previously covered.

    @Test
    fun `stop after a spawn failure still ends STOPPED, never stuck FAILED`() = runTest {
        val launcher = FakeB45AProcessLauncher(shouldFailToLaunch = true)
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_TUN_CIDR)
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)

        runtime.stop()

        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)
    }

    @Test
    fun `start succeeds again after a prior failed start was stopped`() = runTest {
        val launcher = FakeB45AProcessLauncher(shouldFailToLaunch = true)
        val runtime = B45ARuntime(launcher, FakeB45ATunFdBridge(), FakeB45AVpnProtectBridge(), FakeB45AVpnProtector(), this)

        val binary = existingBinaryPath()
        val workingDir = tempWorkingDir()
        runtime.start(binary, 1, workingDir, TEST_TUN_CIDR)
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        runtime.stop()
        assertEquals(B45ARuntimePhase.STOPPED, runtime.status.value.phase)

        // Same launcher still fails, so start() still returns false - but
        // the important proof is launchCount reaching 2: canStart() genuinely
        // permitted a FRESH real attempt from STOPPED after the FAILED->
        // STOPPED cycle (a double-start REJECTION would never even call
        // launcher.launch() a second time, leaving launchCount at 1).
        val secondAttempt = runtime.start(binary, 2, workingDir, TEST_TUN_CIDR)

        assertFalse(secondAttempt) // fails again for the same injected reason - expected, not a rejection
        assertEquals(B45ARuntimePhase.FAILED, runtime.status.value.phase)
        assertEquals(2, launcher.launchCount) // a genuine second real attempt was made, not silently skipped
    }
}
