@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import java.io.FileDescriptor
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private const val TEST_CIDR = ShadowsocksTunConfig.CIDR
private val TARGET = ShadowsocksRuntimeTarget(host = "203.0.113.10", port = 8388, method = "2022-blake3-aes-256-gcm", keyBase64 = "REDACTED-TEST-KEY-BASE64==")

/** A plain, unopened FileDescriptor - never dereferenced by any fake, so its own "closed" concept is irrelevant here; only identity (===) matters for the ownership tests below. */
private val TEST_TUN_FD = FileDescriptor()

/**
 * B45B-3 (Phase 16) - fakes only, never a real native process/socket. Covers
 * the failure/cleanup matrix (Phase 12) plus the secret-hygiene guarantees
 * (Phase 7/8/16 items 4/5) at the runtime-orchestration level.
 */
class ShadowsocksRuntimeTest {

    private fun tempWorkingDir(): File = kotlin.io.path.createTempDirectory("shadowsocks-test").toFile().apply { deleteOnExit() }
    private fun existingBinaryPath(): String = kotlin.io.path.createTempFile("fake-sslocal", "").toFile().apply { deleteOnExit() }.absolutePath

    // 7. binary missing -> typed failure
    @Test
    fun `missing binary fails before touching the protect bridge`() = runTest {
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val runtime = ShadowsocksRuntime(FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this)

        val started = runtime.start("/does/not/exist/sslocal", TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)

        assertFalse(started)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.BinaryMissing)
        assertEquals(0, protectBridge.startCalls)
    }

    // 9. protect bridge startup failure -> cleanup
    @Test
    fun `protect listener failure fails the whole start attempt and deletes the runtime config`() = runTest {
        val protectBridge = FakeShadowsocksVpnProtectBridge(throwOnStart = true)
        val launcher = FakeShadowsocksProcessLauncher()
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this)

        val started = runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertFalse(started)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.ProtectListenerFailed)
        assertEquals(0, launcher.launchCount)
        assertTrue("runtime config must not remain on disk after cleanup", workingDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty())
    }

    // 8. process spawn failure -> cleanup
    @Test
    fun `failed spawn stops the protect bridge, deletes the config, and transitions to FAILED`() = runTest {
        val launcher = FakeShadowsocksProcessLauncher(shouldFailToLaunch = true)
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this)

        val started = runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertFalse(started)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.SpawnFailed)
        assertEquals(1, protectBridge.stopCalls)
        assertTrue(workingDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty())
    }

    // 4/5. secret never in argv, never in typed state/toString
    @Test
    fun `secret key never appears in the sslocal argv or in typed error state`() = runTest {
        val launcher = FakeShadowsocksProcessLauncher()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)

        runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)

        val args = launcher.lastArgs!!
        assertFalse(args.any { it.contains(TARGET.keyBase64) })
        assertFalse(args.contains("-k"))
        assertTrue(args.contains("-c"))
        assertFalse(runtime.status.value.toString().contains(TARGET.keyBase64))
        assertFalse(TARGET.toString().contains(TARGET.keyBase64))
    }

    // 3. valid fake credential -> runtime config built (config file exists during the run, deleted after RUNNING is reached)
    @Test
    fun `start writes a runtime config file then deletes it once startup is confirmed`() = runTest {
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(
            FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(result = ShadowsocksTunFdBridgeState.FD_SENT),
            FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertEquals(ShadowsocksRuntimePhase.RUNNING, runtime.status.value.phase)
        assertTrue("config file must be deleted after confirmed startup", workingDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty())
    }

    // 6. runtime config cleanup on handoff failure
    @Test
    fun `tun fd handoff failure cleans up and transitions to FAILED`() = runTest {
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(
            FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(result = ShadowsocksTunFdBridgeState.FAILED),
            protectBridge, FakeShadowsocksVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.TunFdHandoffTimedOut)
        assertEquals(1, protectBridge.stopCalls)
        assertTrue(workingDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty())
    }

    // 12. unexpected process exit -> Failed + cleanup
    @Test
    fun `unexpected process exit while RUNNING transitions to FAILED and stops the protect bridge`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val runtime = ShadowsocksRuntime(
            launcher, FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)
        assertEquals(ShadowsocksRuntimePhase.RUNNING, runtime.status.value.phase)

        process.simulateUnexpectedExit(1)

        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.ProcessExitedUnexpectedly)
        assertEquals(1, protectBridge.stopCalls)
    }

    // 13. normal disconnect -> complete cleanup
    @Test
    fun `stop requests process termination, stops the protect bridge, and ends STOPPED`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this)

        runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)
        runtime.stop()

        assertTrue(process.stopRequested)
        assertEquals(1, protectBridge.stopCalls)
        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)
    }

    @Test
    fun `stop force-kills a process that does not exit gracefully`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)

        runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)
        runtime.stop()

        assertTrue(process.stopRequested)
        assertTrue(process.forceStopped)
    }

    // --- B45B-3P physical-crash-driven fix: normal Stop must also remove
    // tun_fd_path, which sslocal itself binds/listens on (Android is only
    // the CLIENT - see ShadowsocksTunFdBridge's own docs) and was physically
    // observed NOT to unlink on a plain SIGTERM.

    // 1/2/3. normal stop removes tun_fd_path, protect_path is stopped, and runtime_config (if still present) is removed.
    @Test
    fun `normal stop removes the tun-fd UDS left behind by sslocal, alongside the protect bridge and runtime config`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(), this)

        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)
        // Simulates sslocal's own bound-but-never-unlinked socket file - real
        // production behavior physically observed, never created by any
        // fake in this test.
        val tunUds = File(workingDir, "tun_fd_path").apply { writeText("") }

        runtime.stop()

        assertFalse("tun_fd_path must be removed by a normal Stop, not only the next start's stale sweep", tunUds.exists())
        assertEquals(1, protectBridge.stopCalls)
        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)
    }

    // 4. second stop remains idempotent even with the new cleanup step.
    @Test
    fun `stop remains idempotent after the tun-fd UDS cleanup fix`() = runTest {
        val runtime = ShadowsocksRuntime(FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET)

        runtime.stop()
        runtime.stop() // must not throw or re-run cleanup against a null process

        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)
    }

    // 5. cleanup never touches anything outside the two named ephemeral files - the encrypted credential repository lives in an entirely different directory (noBackupFilesDir) never passed here.
    @Test
    fun `stop never removes a file outside the two known ephemeral filenames`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)
        val unrelated = File(workingDir, "unrelated.txt").apply { writeText("keep me") }

        runtime.stop()

        assertTrue(unrelated.exists())
    }

    // 6. cleanup happens after process stop/reap - requestStop() must have actually run (proof the termination step executed) before/alongside the UDS removal, never skipped.
    @Test
    fun `stop requests process termination before completing ephemeral cleanup`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)
        val tunUds = File(workingDir, "tun_fd_path").apply { writeText("") }

        runtime.stop()

        assertTrue("process termination must have been requested", process.stopRequested)
        assertFalse("UDS cleanup must have completed by the time stop() returns", tunUds.exists())
    }

    // 7. a stale path that cannot actually be removed during stop() must not resurrect Connected - stop() always ends STOPPED/IDLE, never leaves a phantom RUNNING/Error state.
    @Test
    fun `a tun-fd UDS that cannot be deleted during stop does not prevent reaching STOPPED`() = runTest {
        val process = FakeShadowsocksSpawnedProcess()
        val launcher = FakeShadowsocksProcessLauncher(processFactory = { process })
        val workingDir = tempWorkingDir()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)
        // A non-empty directory standing where the UDS filename is expected - File.delete() cannot remove it.
        val stuck = File(workingDir, "tun_fd_path").apply { mkdirs() }
        File(stuck, "child").writeText("blocks delete")

        runtime.stop()

        assertEquals("a best-effort cleanup failure must never block reaching STOPPED", ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)
    }

    // 14. double disconnect idempotent
    @Test
    fun `stop on an already-stopped runtime is a no-op`() {
        val protectBridge = FakeShadowsocksVpnProtectBridge()
        val runtime = ShadowsocksRuntime(
            FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(), protectBridge, FakeShadowsocksVpnProtector(),
            kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Unconfined),
        )

        runtime.stop()
        runtime.stop()

        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)
        assertEquals(0, protectBridge.stopCalls)
    }

    // 15. connect after prior failure can start cleanly
    @Test
    fun `start succeeds again after a prior failed start was stopped`() = runTest {
        val launcher = FakeShadowsocksProcessLauncher(shouldFailToLaunch = true)
        val workingDir = tempWorkingDir()
        val binary = existingBinaryPath()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)

        runtime.start(binary, TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        runtime.stop()
        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)

        val secondAttempt = runtime.start(binary, TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertFalse(secondAttempt) // same launcher still fails - the point is a fresh attempt was genuinely made
        assertEquals(2, launcher.launchCount)
    }

    // Double-start rejected while a session is in flight/running.
    @Test
    fun `second start call while RUNNING is rejected`() = runTest {
        val launcher = FakeShadowsocksProcessLauncher()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        val workingDir = tempWorkingDir()
        val binary = existingBinaryPath()

        assertTrue(runtime.start(binary, TEST_TUN_FD, workingDir, TEST_CIDR, TARGET))
        val secondStart = runtime.start(binary, TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertFalse(secondStart)
        assertEquals(1, launcher.launchCount)
    }

    // 16. TUN ownership - ShadowsocksRuntime.start() takes a plain FileDescriptor
    // (never an Int, never a second ParcelFileDescriptor it could adopt/close -
    // java.io.FileDescriptor exposes no close()/adopt API at all, so this
    // class is structurally incapable of taking ownership even by mistake).
    // Items 1-3 (bridge never adopts, original owner stays valid, original
    // owner never closed by the bridge) follow from this same type-level
    // guarantee plus RealShadowsocksTunFdBridge's own docs (verified against
    // AOSP LocalSocketImpl source, not unit-testable here without a real
    // Android runtime - see this class's own package docs on that limit).
    @Test
    fun `the exact same FileDescriptor instance passed to start reaches the tun-fd bridge unchanged`() = runTest {
        val tunFdBridge = FakeShadowsocksTunFdBridge()
        val runtime = ShadowsocksRuntime(
            FakeShadowsocksProcessLauncher(), tunFdBridge, FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        assertTrue(runtime.start(existingBinaryPath(), TEST_TUN_FD, tempWorkingDir(), TEST_CIDR, TARGET))

        assertSame("the runtime must forward the exact instance, never a copy/replacement", TEST_TUN_FD, tunFdBridge.lastTunFd)
    }

    // --- Phase 4 (B45B-3P) - crash-resilient stale ephemeral state sweep ---

    // 7/8/9. stale plaintext config / protect UDS / TUN UDS all removed before a new config is written.
    @Test
    fun `sweepStaleEphemeralState removes a stale plaintext runtime config, protect UDS, and TUN UDS`() {
        val dir = tempWorkingDir()
        val config = File(dir, "runtime_config.json").apply { writeText("stale plaintext") }
        val protectUds = File(dir, "protect_path").apply { writeText("stale") }
        val tunUds = File(dir, "tun_fd_path").apply { writeText("stale") }

        val result = sweepStaleEphemeralState(protectUds, tunUds, config)

        assertTrue(result)
        assertFalse(config.exists())
        assertFalse(protectUds.exists())
        assertFalse(tunUds.exists())
    }

    // 10. the encrypted credential repository lives in a different directory entirely (noBackupFilesDir, never workingDir) - structurally never passed to this function, so never at risk.
    // 11. a file outside the explicit ephemeral set passed in is left untouched.
    @Test
    fun `a file not named in the ephemeral set is never removed`() {
        val dir = tempWorkingDir()
        val unrelated = File(dir, "unrelated.txt").apply { writeText("keep me") }
        val config = File(dir, "runtime_config.json") // does not exist - nothing to sweep

        val result = sweepStaleEphemeralState(config)

        assertTrue(result)
        assertTrue("a file never named in the ephemeral set must survive", unrelated.exists())
    }

    // 12. idempotent - sweeping an already-clean directory (or sweeping twice) is a no-op success, never an error.
    @Test
    fun `sweep is idempotent - a second sweep of an already-clean directory still succeeds`() {
        val dir = tempWorkingDir()
        val config = File(dir, "runtime_config.json").apply { writeText("stale") }

        assertTrue(sweepStaleEphemeralState(config))
        assertTrue(sweepStaleEphemeralState(config)) // already gone - still succeeds
    }

    // 13. cleanup failure prevents process spawn - a stale path that cannot actually be removed (here: a non-empty directory standing where the plaintext config filename is expected) fails closed.
    @Test
    fun `start fails closed with StaleStateCleanupFailed when a stale path cannot be removed`() = runTest {
        val workingDir = tempWorkingDir()
        // A non-empty directory at the runtime config's own path - File.delete()
        // cannot remove a non-empty directory, so the sweep must fail.
        val stuck = File(workingDir, "runtime_config.json").apply { mkdirs() }
        File(stuck, "child").writeText("blocks delete")
        val launcher = FakeShadowsocksProcessLauncher()
        val runtime = ShadowsocksRuntime(launcher, FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)

        val started = runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertFalse(started)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is ShadowsocksRuntimeError.StaleStateCleanupFailed)
        assertEquals("must never spawn sslocal after a failed stale-state sweep", 0, launcher.launchCount)
    }

    // 14. normal startup still sweeps stale state from a PRIOR dead session, then proceeds and removes its OWN runtime_config after a successful handoff (regression guard alongside the item-3 test above).
    @Test
    fun `start sweeps a stale config left by a prior abnormal death, then proceeds normally`() = runTest {
        val workingDir = tempWorkingDir()
        File(workingDir, "runtime_config.json").apply { writeText("leftover plaintext from a crashed session") }
        val runtime = ShadowsocksRuntime(
            FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(result = ShadowsocksTunFdBridgeState.FD_SENT),
            FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this,
            ioDispatcher = UnconfinedTestDispatcher(testScheduler),
        )

        runtime.start(existingBinaryPath(), TEST_TUN_FD, workingDir, TEST_CIDR, TARGET)

        assertEquals(ShadowsocksRuntimePhase.RUNNING, runtime.status.value.phase)
        assertTrue(workingDir.listFiles { f -> f.name.endsWith(".json") }.isNullOrEmpty())
    }
}
