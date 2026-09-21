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
 * B46-3A Part F, ORDER B (tun2socks first) - run in isolation
 * (`am instrument -w -e class ...NativeTun2SocksTun2SocksFirstOrderInstrumentedTest`)
 * against a freshly force-stopped app process, so this genuinely proves
 * "tun2socks Go runtime loaded/used BEFORE the Xray Go runtime is ever
 * touched, in the same process" - the reverse order from
 * [NativeTun2SocksXrayFirstOrderInstrumentedTest].
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksTun2SocksFirstOrderInstrumentedTest {

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
    fun tun2socks_first_then_xray_real_lifecycle() {
        // Step 1: tun2socks native library loaded/used first in this fresh
        // process, including a real TUN start/stop lifecycle.
        assertFalse(NativeTun2SocksBridge.isStarted())

        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_START))
        val startResult = awaitStatus()
        assertTrue("expected Started, got $startResult", startResult is NativeTun2SocksSpikeStatus.Started)
        assertTrue(NativeTun2SocksBridge.isStarted())

        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP))
        awaitIdle()
        assertFalse(NativeTun2SocksBridge.isStarted())

        // Step 2: only now does the real Xray Go runtime get entered.
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)
    }
}
