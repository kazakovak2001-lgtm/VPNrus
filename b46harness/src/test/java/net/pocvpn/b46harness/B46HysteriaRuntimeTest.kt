@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.b46harness

import java.io.File
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2P - unit tests for [B46HysteriaRuntime]'s orchestration logic against
 * fakes (no real process, TUN, tun2socks AAR, or Unix-domain socket). See
 * `docs/B46_2P_HYSTERIA2_ANDROID_PHYSICAL_VALIDATION.md` for the physical
 * evidence these mechanics were exercised against on a real device.
 */
class B46HysteriaRuntimeTest {

    private fun tempWorkingDir(): File = kotlin.io.path.createTempDirectory("b46-test").toFile().apply { deleteOnExit() }
    private fun existingBinaryPath(): String {
        val f = kotlin.io.path.createTempFile("fake-hysteria", "").toFile()
        f.deleteOnExit()
        return f.absolutePath
    }

    private fun newRuntime(
        protectBridge: FakeB46HysteriaVpnProtectBridge = FakeB46HysteriaVpnProtectBridge(),
        launcher: FakeB46HysteriaProcessLauncher = FakeB46HysteriaProcessLauncher(),
        tun2Socks: B46Tun2SocksBridge = FakeB46Tun2SocksBridge(),
        scope: kotlinx.coroutines.CoroutineScope,
    ) = B46HysteriaRuntime(protectBridge, launcher, tun2Socks, scope)

    @Test
    fun `happy path progresses STARTING through TUN_BRIDGE_READY to RUNTIME_STARTED`() = runTest {
        val runtime = newRuntime(scope = this)
        runtime.starting()
        runtime.tunEstablished()
        assertTrue(runtime.startBridge(dupFd = 42, mtu = 1400, socksAddr = "127.0.0.1:41080"))
        assertEquals(B46HysteriaSpikePhase.TUN_BRIDGE_READY, runtime.status.value.phase)

        val started = runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())
        assertTrue(started)
        assertEquals(B46HysteriaSpikePhase.RUNTIME_STARTED, runtime.status.value.phase)
        assertEquals(1234, runtime.status.value.runtimePid)
    }

    // bridge-start failure
    @Test
    fun `bridge-start failure moves to ERROR with BridgeStartFailed and never reaches RUNTIME_STARTED`() = runTest {
        val tun2Socks = FakeB46Tun2SocksBridge(startResult = B46Tun2SocksResult.Failed("bridge.Bridge class not found"))
        val runtime = newRuntime(tun2Socks = tun2Socks, scope = this)
        runtime.starting()
        runtime.tunEstablished()

        val ok = runtime.startBridge(dupFd = 1, mtu = 1400, socksAddr = "127.0.0.1:1")

        assertFalse(ok)
        assertEquals(B46HysteriaSpikePhase.ERROR, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B46HysteriaSpikeError.BridgeStartFailed)
    }

    // debug artifact missing -> typed fail-closed error (real RealB46Tun2SocksBridge, no fake)
    @Test
    fun `real tun2socks bridge with no AAR present fails closed with a typed error, never a raw NoClassDefFoundError`() = runTest {
        val runtime = newRuntime(tun2Socks = RealB46Tun2SocksBridge(), scope = this)
        runtime.starting()
        runtime.tunEstablished()

        val ok = runtime.startBridge(dupFd = 1, mtu = 1400, socksAddr = "127.0.0.1:1")

        assertFalse(ok)
        assertEquals(B46HysteriaSpikePhase.ERROR, runtime.status.value.phase)
        assertTrue(runtime.status.value.lastError is B46HysteriaSpikeError.BridgeStartFailed)
    }

    // runtime-exit (child process exit) failure
    @Test
    fun `unexpected child process exit clears runtimePid and moves to ERROR`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        launcher.lastLaunched!!.simulateUnexpectedExit(exitCode = 137)

        assertEquals(B46HysteriaSpikePhase.ERROR, runtime.status.value.phase)
        assertEquals(null, runtime.status.value.runtimePid)
        assertEquals(137, runtime.status.value.exitCode)
        assertTrue(runtime.status.value.lastError is B46HysteriaSpikeError.RuntimeExitedUnexpectedly)
    }

    // 4. unexpected child exit deletes the generated child config (PRE-MERGE HARDENING CORRECTION round 2)
    @Test
    fun `unexpected child exit deletes the generated child config file`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        val workingDir = tempWorkingDir()
        runtime.startChild(existingBinaryPath(), workingDir, testConfig(), FakeB46HysteriaVpnProtector())
        val configFile = File(workingDir, "b46-hysteria-config.json")
        assertTrue("config file should exist right after a successful startChild", configFile.exists())

        launcher.lastLaunched!!.simulateUnexpectedExit(exitCode = 1)

        assertFalse("the child died - its config file (containing auth/obfs) must not remain at rest", configFile.exists())
    }

    // 5. unexpected child exit deletes the protect socket artifact
    @Test
    fun `unexpected child exit deletes the protect socket file`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        val workingDir = tempWorkingDir()
        // The fake protect bridge doesn't create a real socket file, so
        // create one ourselves at the exact path the real runtime uses, to
        // prove the RUNTIME's own cleanup call (not the bridge's) deletes it.
        val protectSocketFile = File(workingDir, "b46-protect.sock")
        workingDir.mkdirs()
        protectSocketFile.writeText("")
        runtime.startChild(existingBinaryPath(), workingDir, testConfig(), FakeB46HysteriaVpnProtector())
        assertTrue(protectSocketFile.exists())

        launcher.lastLaunched!!.simulateUnexpectedExit(exitCode = 1)

        assertFalse("the protect socket artifact must not remain after the child has already died", protectSocketFile.exists())
    }

    // 6. later explicit stop() from ERROR is still safe/idempotent after this early cleanup
    @Test
    fun `stop after unexpected child exit is safe, idempotent, and never double-deletes or throws`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val protectBridge = FakeB46HysteriaVpnProtectBridge()
        val runtime = newRuntime(launcher = launcher, protectBridge = protectBridge, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        launcher.lastLaunched!!.simulateUnexpectedExit(exitCode = 1)
        assertEquals(B46HysteriaSpikePhase.ERROR, runtime.status.value.phase)
        assertEquals(1, protectBridge.stopCalls) // already stopped once by onProcessExitedUnexpectedly

        runtime.stop() // must not throw despite configFile/protectSocketFile already being null

        assertEquals(B46HysteriaSpikePhase.STOPPED, runtime.status.value.phase)
        assertEquals(2, protectBridge.stopCalls) // stop()'s own call - protectBridge.stop() itself is idempotent

        runtime.stop() // second call: canStop() is now false, must be a pure no-op

        assertEquals(B46HysteriaSpikePhase.STOPPED, runtime.status.value.phase)
        assertEquals(2, protectBridge.stopCalls) // not called a third time
    }

    // FD-protect negative ACK -> fail closed, never FD_CONTROL_READY
    @Test
    fun `FD-protect negative ack does not reach FD_CONTROL_READY and records a failure`() = runTest {
        val protectBridge = FakeB46HysteriaVpnProtectBridge()
        val runtime = newRuntime(protectBridge = protectBridge, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector(result = false))

        val succeeded = protectBridge.simulateRequest(fd = 7)

        assertFalse(succeeded)
        assertEquals(B46HysteriaSpikePhase.RUNTIME_STARTED, runtime.status.value.phase) // never advanced
        assertEquals(1, runtime.status.value.fdControlRequestCount)
        assertEquals(1, runtime.status.value.fdControlFailureCount)
    }

    // FD-protect success -> FD_CONTROL_READY
    @Test
    fun `FD-protect success advances RUNTIME_STARTED to FD_CONTROL_READY exactly once`() = runTest {
        val protectBridge = FakeB46HysteriaVpnProtectBridge()
        val runtime = newRuntime(protectBridge = protectBridge, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector(result = true))

        protectBridge.simulateRequest(fd = 7)
        assertEquals(B46HysteriaSpikePhase.FD_CONTROL_READY, runtime.status.value.phase)

        // A second successful request must not throw/regress the phase.
        protectBridge.simulateRequest(fd = 8)
        assertEquals(B46HysteriaSpikePhase.FD_CONTROL_READY, runtime.status.value.phase)
        assertEquals(2, runtime.status.value.fdControlRequestCount)
        assertEquals(0, runtime.status.value.fdControlFailureCount)
    }

    // DATA_PLANE_READY cannot occur before FD_CONTROL_READY
    @Test
    fun `markDataPlaneReady before FD_CONTROL_READY throws and never sets DATA_PLANE_READY`() = runTest {
        val runtime = newRuntime(scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())
        assertEquals(B46HysteriaSpikePhase.RUNTIME_STARTED, runtime.status.value.phase)

        try {
            runtime.markDataPlaneReady()
            org.junit.Assert.fail("expected IllegalStateException - FD_CONTROL_READY not yet reached")
        } catch (expected: IllegalStateException) {
            // expected
        }
        assertNotEquals(B46HysteriaSpikePhase.DATA_PLANE_READY, runtime.status.value.phase)
    }

    @Test
    fun `markDataPlaneReady after FD_CONTROL_READY succeeds`() = runTest {
        val protectBridge = FakeB46HysteriaVpnProtectBridge()
        val runtime = newRuntime(protectBridge = protectBridge, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector(result = true))
        protectBridge.simulateRequest(fd = 1)
        assertEquals(B46HysteriaSpikePhase.FD_CONTROL_READY, runtime.status.value.phase)

        runtime.markDataPlaneReady()
        assertEquals(B46HysteriaSpikePhase.DATA_PLANE_READY, runtime.status.value.phase)
    }

    // stop idempotency
    @Test
    fun `stop is idempotent - calling it twice never throws and stays STOPPED`() = runTest {
        val tun2Socks = FakeB46Tun2SocksBridge()
        val protectBridge = FakeB46HysteriaVpnProtectBridge()
        val runtime = newRuntime(protectBridge = protectBridge, tun2Socks = tun2Socks, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        runtime.stop()
        assertEquals(B46HysteriaSpikePhase.STOPPED, runtime.status.value.phase)
        assertEquals(1, tun2Socks.stopCalls)
        assertEquals(1, protectBridge.stopCalls)

        runtime.stop() // second call: no-op, no throw
        assertEquals(B46HysteriaSpikePhase.STOPPED, runtime.status.value.phase)
        assertEquals(1, tun2Socks.stopCalls) // not called again
    }

    // restart from STOPPED
    @Test
    fun `restart from STOPPED works and produces a new pid`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher(processFactory = { FakeB46HysteriaSpawnedProcess(pid = 111) })
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())
        assertEquals(111, runtime.status.value.runtimePid)
        runtime.stop()
        assertTrue(runtime.canStart())

        val launcher2 = FakeB46HysteriaProcessLauncher(processFactory = { FakeB46HysteriaSpawnedProcess(pid = 222) })
        val runtime2 = newRuntime(launcher = launcher2, scope = this)
        runtime2.starting()
        runtime2.tunEstablished()
        runtime2.startBridge(1, 1400, "127.0.0.1:1")
        runtime2.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        assertEquals(222, runtime2.status.value.runtimePid)
        assertNotEquals(runtime.status.value.runtimePid, runtime2.status.value.runtimePid)
    }

    // no direct restart from ERROR without cleanup
    @Test
    fun `canStart is false from ERROR - must stop first`() = runTest {
        val tun2Socks = FakeB46Tun2SocksBridge(startResult = B46Tun2SocksResult.Failed("boom"))
        val runtime = newRuntime(tun2Socks = tun2Socks, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")

        assertEquals(B46HysteriaSpikePhase.ERROR, runtime.status.value.phase)
        assertFalse(runtime.canStart())

        runtime.stop()
        assertEquals(B46HysteriaSpikePhase.STOPPED, runtime.status.value.phase)
        assertTrue(runtime.canStart())
    }

    // runtime PID ownership correctness
    @Test
    fun `runtimePid reflects the real spawned process pid, not a placeholder`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher(processFactory = { FakeB46HysteriaSpawnedProcess(pid = 9876) })
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        assertEquals(9876, runtime.status.value.runtimePid)
    }

    // debug artifact (binary) missing -> typed fail-closed error
    @Test
    fun `startChild with missing binary path fails closed with typed BinaryMissing, never spawns`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")

        val started = runtime.startChild("/nonexistent/path/libnovahysteria.so", tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        assertFalse(started)
        assertEquals(0, launcher.launchCount)
        assertTrue(runtime.status.value.lastError is B46HysteriaSpikeError.BinaryMissing)
    }

    // no secret is passed in child argv (PRE-MERGE HARDENING CORRECTION regression guard)
    @Test
    fun `child process args never contain the auth secret - only a config-file path`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")

        val config = testConfig() // auth = "test-secret-auth-value"
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), config, FakeB46HysteriaVpnProtector())

        val args = launcher.lastArgs
        assertTrue("expected --config-file in args: $args", args != null && args.contains("--config-file"))
        assertEquals("expected exactly 2 args (--config-file <path>)", 2, args!!.size)
        assertFalse("no arg may contain the auth secret: $args", args.any { it.contains(config.auth) })
        assertFalse("no arg may be --auth: $args", args.contains("--auth"))
    }

    // child log-line observation (QUIC handshake / SOCKS5 listener), additive to the state machine
    @Test
    fun `child log lines set quicHandshakeConnected and socksListenerReady without touching phase`() = runTest {
        val launcher = FakeB46HysteriaProcessLauncher()
        val runtime = newRuntime(launcher = launcher, scope = this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        runtime.startChild(existingBinaryPath(), tempWorkingDir(), testConfig(), FakeB46HysteriaVpnProtector())

        launcher.lastLaunched!!.simulateLogLine("2026/09/20 05:31:03 connected: udpEnabled=true tx=0")
        assertTrue(runtime.status.value.quicHandshakeConnected)
        assertFalse(runtime.status.value.socksListenerReady)
        assertEquals(B46HysteriaSpikePhase.RUNTIME_STARTED, runtime.status.value.phase)

        launcher.lastLaunched!!.simulateLogLine("2026/09/20 05:31:03 SOCKS5_LISTENING addr=127.0.0.1:41080")
        assertTrue(runtime.status.value.socksListenerReady)
    }
}
