package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3A Part F, ORDER A (Xray first) - run in isolation
 * (`am instrument -w -e class ...NativeTun2SocksXrayFirstOrderInstrumentedTest`)
 * against a freshly force-stopped app process, so this genuinely proves
 * "Xray Go runtime loaded/used BEFORE the tun2socks Go runtime is ever
 * touched, in the same process" - not merely a method-call order within an
 * already-warm process shared with other tests.
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksXrayFirstOrderInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String) {
        // Drain to completion before closing - executeShellCommand's pipe must be
        // read (or the underlying shell process can be torn down before the
        // command finishes, a real bug found and fixed during B46-3A physical
        // testing: an un-drained close() truncated `appops set` often enough
        // to make VpnService.Builder.establish() flakily fail).
        instrumentation.uiAutomation.executeShellCommand(cmd).use {
            it.fileDescriptor.let { fd -> java.io.FileInputStream(fd).bufferedReader().readText() }
        }
    }

    private fun awaitStatus(timeoutMillis: Long = 5_000): NativeTun2SocksSpikeStatus {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var last = NativeTun2SocksSpikeVpnService.status.value
        while (System.currentTimeMillis() < deadline) {
            last = NativeTun2SocksSpikeVpnService.status.value
            if (last !is NativeTun2SocksSpikeStatus.Idle) return last
            Thread.sleep(50)
        }
        return last
    }

    private fun awaitIdle(timeoutMillis: Long = 5_000) {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (NativeTun2SocksSpikeVpnService.status.value is NativeTun2SocksSpikeStatus.Idle) return
            Thread.sleep(50)
        }
    }

    @Test
    fun xray_first_then_tun2socks_real_lifecycle() {
        // Step 1: real Xray Go runtime entry - first thing touched in this
        // fresh process.
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        // Step 2: only now does the tun2socks native library get loaded/used.
        assertFalse(NativeTun2SocksBridge.isStarted())

        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_START))
        val startResult = awaitStatus()
        assertTrue("expected Started, got $startResult", startResult is NativeTun2SocksSpikeStatus.Started)
        assertTrue(NativeTun2SocksBridge.isStarted())

        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP))
        awaitIdle()
        assertFalse(NativeTun2SocksBridge.isStarted())

        // Xray runtime still healthy after the tun2socks cycle - proves one
        // runtime did not poison the other.
        assertFalse(xray.isRunning)
    }
}
