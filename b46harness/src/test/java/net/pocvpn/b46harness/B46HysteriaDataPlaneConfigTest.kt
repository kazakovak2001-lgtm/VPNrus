@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package net.pocvpn.b46harness

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2P - PRE-MERGE HARDENING CORRECTION (round 2) regression tests: the
 * runtime credential file must be consumed (deleted) the moment it is
 * successfully parsed into memory - BEFORE TUN/bridge/child startup
 * continues - not deferred to `stop()`/failure cleanup. Uses
 * [B46HysteriaDataPlaneConfig]'s narrow, `BuildConfig`-independent
 * `resolve(filesDir, host, port, sni, insecureStr)` seam so these tests
 * are portable (no dependency on the gitignored local
 * `b46-hysteria-dataplane.properties` file's contents).
 */
class B46HysteriaDataPlaneConfigTest {

    private fun tempFilesDir(): File = createTempDirectory("b46-dpc-test").toFile().apply { deleteOnExit() }

    private fun provisionCredential(filesDir: File, auth: String = "test-secret-auth-value"): File {
        val file = B46HysteriaRuntimeCredential.credentialFile(filesDir)
        file.parentFile?.mkdirs()
        file.writeText("auth=$auth\n")
        return file
    }

    // 1. successful resolution consumes/deletes the provisioning credential
    @Test
    fun `successful resolve deletes the runtime credential file before returning Valid`() {
        val filesDir = tempFilesDir()
        val credentialFile = provisionCredential(filesDir)
        assertTrue(credentialFile.exists())

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "203.0.113.1", port = "34443", sni = "example.test", insecureStr = "true")

        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Valid)
        assertFalse("runtime credential file must be deleted immediately after a successful parse", credentialFile.exists())
    }

    @Test
    fun `resolved config carries the secret in memory even though the file is already gone`() {
        val filesDir = tempFilesDir()
        provisionCredential(filesDir, auth = "carried-in-memory-value")

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "203.0.113.1", port = "34443", sni = "example.test", insecureStr = "true")

        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Valid)
        val config = (result as B46HysteriaDataPlaneConfig.Result.Valid).config
        // The value was captured into memory BEFORE the file was deleted - this is the whole point.
        org.junit.Assert.assertEquals("carried-in-memory-value", config.auth)
    }

    @Test
    fun `missing runtime credential fails closed without needing a file to delete`() {
        val filesDir = tempFilesDir() // nothing provisioned

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "203.0.113.1", port = "34443", sni = "example.test", insecureStr = "true")

        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Invalid)
        assertFalse(B46HysteriaRuntimeCredential.credentialFile(filesDir).exists())
    }

    @Test
    fun `blank host fails closed and never touches the runtime credential file`() {
        val filesDir = tempFilesDir()
        val credentialFile = provisionCredential(filesDir)

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "", port = "34443", sni = "example.test", insecureStr = "true")

        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Invalid)
        // Host/port are checked before the credential file is ever touched -
        // a blank-host failure must not consume a still-good credential.
        assertTrue("a config-level failure must not consume a still-valid credential file", credentialFile.exists())
    }

    // 2 & 3. bridge-start / child-start failure leave no runtime credential
    // file - by construction, since resolve() already deleted it before
    // either could run. These integration-style tests lock in that
    // ordering as an invariant against future refactors.
    @Test
    fun `bridge-start failure after a successful resolve leaves no runtime credential file`() = runTest {
        val filesDir = tempFilesDir()
        val credentialFile = provisionCredential(filesDir)

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "203.0.113.1", port = "34443", sni = "example.test", insecureStr = "true")
        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Valid)
        assertFalse(credentialFile.exists()) // already gone before bridge startup is even attempted

        val tun2Socks = FakeB46Tun2SocksBridge(startResult = B46Tun2SocksResult.Failed("simulated bridge failure"))
        val runtime = B46HysteriaRuntime(FakeB46HysteriaVpnProtectBridge(), FakeB46HysteriaProcessLauncher(), tun2Socks, this)
        runtime.starting()
        runtime.tunEstablished()
        val bridgeStarted = runtime.startBridge(dupFd = 1, mtu = 1400, socksAddr = "127.0.0.1:1")

        assertFalse(bridgeStarted)
        assertFalse(credentialFile.exists())
    }

    @Test
    fun `child-start failure after a successful resolve leaves no runtime credential file`() = runTest {
        val filesDir = tempFilesDir()
        val credentialFile = provisionCredential(filesDir)

        val result = B46HysteriaDataPlaneConfig.resolve(filesDir, host = "203.0.113.1", port = "34443", sni = "example.test", insecureStr = "true")
        assertTrue(result is B46HysteriaDataPlaneConfig.Result.Valid)
        val config = (result as B46HysteriaDataPlaneConfig.Result.Valid).config
        assertFalse(credentialFile.exists())

        val runtime = B46HysteriaRuntime(FakeB46HysteriaVpnProtectBridge(), FakeB46HysteriaProcessLauncher(), FakeB46Tun2SocksBridge(), this)
        runtime.starting()
        runtime.tunEstablished()
        runtime.startBridge(1, 1400, "127.0.0.1:1")
        // Missing binary -> startChild fails closed.
        val childStarted = runtime.startChild("/nonexistent/path/libnovahysteria.so", createTempDirectory("b46-dpc-workdir").toFile(), config, FakeB46HysteriaVpnProtector())

        assertFalse(childStarted)
        assertFalse(credentialFile.exists())
    }
}
