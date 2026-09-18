@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.client.vpn.shadowsocks

import java.io.File
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

private const val TEST_CIDR = ShadowsocksTunConfig.CIDR
private val TARGET = ShadowsocksRuntimeTarget(host = "203.0.113.10", port = 8388, method = "2022-blake3-aes-256-gcm", keyBase64 = "REDACTED-TEST-KEY-BASE64==")

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

        val started = runtime.start("/does/not/exist/sslocal", 1, tempWorkingDir(), TEST_CIDR, TARGET)

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

        val started = runtime.start(existingBinaryPath(), 1, workingDir, TEST_CIDR, TARGET)

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

        val started = runtime.start(existingBinaryPath(), 1, workingDir, TEST_CIDR, TARGET)

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

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_CIDR, TARGET)

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

        runtime.start(existingBinaryPath(), 1, workingDir, TEST_CIDR, TARGET)

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

        runtime.start(existingBinaryPath(), 99, workingDir, TEST_CIDR, TARGET)

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

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_CIDR, TARGET)
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

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_CIDR, TARGET)
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

        runtime.start(existingBinaryPath(), 1, tempWorkingDir(), TEST_CIDR, TARGET)
        runtime.stop()

        assertTrue(process.stopRequested)
        assertTrue(process.forceStopped)
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

        runtime.start(binary, 1, workingDir, TEST_CIDR, TARGET)
        assertEquals(ShadowsocksRuntimePhase.FAILED, runtime.status.value.phase)
        runtime.stop()
        assertEquals(ShadowsocksRuntimePhase.STOPPED, runtime.status.value.phase)

        val secondAttempt = runtime.start(binary, 2, workingDir, TEST_CIDR, TARGET)

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

        assertTrue(runtime.start(binary, 1, workingDir, TEST_CIDR, TARGET))
        val secondStart = runtime.start(binary, 2, workingDir, TEST_CIDR, TARGET)

        assertFalse(secondStart)
        assertEquals(1, launcher.launchCount)
    }

    // 16. TUN ownership - the runtime never itself closes the raw tunFd it was given (owned by ShadowsocksVpnService).
    @Test
    fun `runtime never calls back into the caller to close the tun fd it was handed`() = runTest {
        // The fake tun-fd bridge never touches the real fd; this test documents
        // (rather than mechanically enforces beyond compilation) that
        // ShadowsocksRuntime.start()'s only fd-related parameter is a raw Int,
        // never a ParcelFileDescriptor it could take ownership of and close.
        val runtime = ShadowsocksRuntime(FakeShadowsocksProcessLauncher(), FakeShadowsocksTunFdBridge(), FakeShadowsocksVpnProtectBridge(), FakeShadowsocksVpnProtector(), this)
        assertTrue(runtime.start(existingBinaryPath(), 123, tempWorkingDir(), TEST_CIDR, TARGET))
    }
}
