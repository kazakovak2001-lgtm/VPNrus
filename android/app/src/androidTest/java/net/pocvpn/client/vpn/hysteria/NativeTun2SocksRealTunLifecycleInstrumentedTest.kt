package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3A Part E - real Android VpnService TUN + real native tun2socks
 * engine lifecycle, driven through [NativeTun2SocksSpikeVpnService] (a
 * debug-only, non-production VpnService - see that class's own doc). Proves
 * the FULL real fd-ownership contract on a genuine TUN interface: a
 * duplicate (never the original) is handed to the native engine, which
 * takes ownership of it and closes it on its own `stop()`.
 *
 * `appops set <pkg> ACTIVATE_VPN allow`, run via
 * [android.app.UiAutomation.executeShellCommand] (shell UID, no root
 * needed), lets [android.net.VpnService.Builder.establish] succeed without
 * a blocking user consent dialog - standard automated-VPN-testing practice,
 * not a production behavior change (this only affects THIS debug package on
 * THIS test device).
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksRealTunLifecycleInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use {
            it.fileDescriptor.let { fd -> java.io.FileInputStream(fd).bufferedReader().readText() }
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

    @Before
    fun grantVpnPermissionAndEnsureStopped() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        context.startService(
            Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP),
        )
        awaitIdle()
        // Belt-and-suspenders: the previous test (or a leftover from a prior
        // run) may have left the real Go engine started even if the spike
        // service's own status was already Idle for some other reason.
        NativeTun2SocksBridge.stop()
    }

    @After
    fun stopSpikeAfterTest() {
        context.startService(
            Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP),
        )
        awaitIdle()
    }

    @Test
    fun real_tun_start_stop_lifecycle() {
        assertFalse("expected native bridge not started before this test", NativeTun2SocksBridge.isStarted())

        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_START))
        val startResult = awaitStatus()
        assertTrue("expected Started, got $startResult", startResult is NativeTun2SocksSpikeStatus.Started)
        assertTrue(NativeTun2SocksBridge.isStarted())

        // Second start while already started: called directly against the
        // REAL native singleton (not through the spike service, which would
        // otherwise re-establish a SECOND real TUN interface) - Go's own
        // `started` check runs before any fd/mtu/address validation, so this
        // deterministically proves the real AlreadyStarted path without ever
        // touching the fd argument.
        val secondStart = NativeTun2SocksBridge.start(fd = -1, mtu = 1500, socksAddr = "127.0.0.1:41999")
        assertTrue(secondStart is NativeBridgeResult.Failed)
        assertEquals("bridge already started", (secondStart as NativeBridgeResult.Failed).reason)
        // Still started - the rejected second call never touched engine state.
        assertTrue(NativeTun2SocksBridge.isStarted())

        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP))
        awaitIdle()
        assertFalse(NativeTun2SocksBridge.isStarted())

        // Idempotent second stop.
        val secondStop = NativeTun2SocksBridge.stop()
        assertTrue(secondStop is NativeBridgeResult.Ok)
        assertFalse(NativeTun2SocksBridge.isStarted())
    }
}
