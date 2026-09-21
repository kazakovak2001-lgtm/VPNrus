package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

private const val TAG = "B46_3A_Stress"
private const val STRESS_CYCLES = 100

/**
 * B46-3A Part G/H - the load-bearing physical acceptance test: at least 100
 * real native tun2socks start/stop cycles with the real Xray Go runtime
 * loaded in the SAME process, plus a same-process `/proc/self/maps` proof
 * that both `libgojni.so` (Xray) and `libnovatun2socks.so`/
 * `libnovatun2socks_jni.so` (B46-3A) are mapped into this exact process.
 *
 * The real Android-established TUN interface is created ONCE (cycle 1, via
 * [NativeTun2SocksSpikeVpnService]) and REUSED for cycles 2-100 - each
 * subsequent cycle mints a FRESH `ParcelFileDescriptor.dup()` of the SAME
 * original TUN fd (see [NativeTun2SocksSpikeVpnService.currentOriginalTunFileDescriptor]'s
 * own doc for why: this exercises the real native engine's full
 * Insert/Start/Stop lifecycle 100+ times without the overhead/flakiness of
 * re-establishing a real Android VPN interface every cycle). This test
 * FAILS immediately (not merely at the end) on the first cycle that does
 * not report success - no silent swallowing, no retry-until-green.
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksStressInstrumentedTest {

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
    fun stress_100_cycles_same_process_with_xray_loaded() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP))
        awaitIdle()
        NativeTun2SocksBridge.stop()

        // Real Xray Go runtime, loaded once, kept resident for the whole run.
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        // Cycle 1: establish the real TUN via the spike service.
        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_START))
        val firstStart = awaitStatus()
        assertTrue("cycle 1 expected Started, got $firstStart", firstStart is NativeTun2SocksSpikeStatus.Started)
        assertTrue(NativeTun2SocksBridge.isStarted())

        // Same-process map proof (Part H) while both runtimes are loaded and
        // the native bridge is genuinely running.
        val pid = Process.myPid()
        val maps = File("/proc/self/maps").readText()
        val hasXray = maps.contains("libgojni.so")
        val hasNativeBridge = maps.contains("libnovatun2socks.so")
        val hasJniShim = maps.contains("libnovatun2socks_jni.so")
        Log.i(TAG, "same-process maps proof, pid=$pid libgojni.so=$hasXray libnovatun2socks.so=$hasNativeBridge libnovatun2socks_jni.so=$hasJniShim")
        maps.lineSequence().filter { it.contains("libgojni.so") || it.contains("libnovatun2socks") }.take(6).forEach {
            Log.i(TAG, "maps: $it")
        }
        assertTrue("expected libgojni.so mapped in pid=$pid", hasXray)
        assertTrue("expected libnovatun2socks.so mapped in pid=$pid", hasNativeBridge)
        assertTrue("expected libnovatun2socks_jni.so mapped in pid=$pid", hasJniShim)

        NativeTun2SocksBridge.stop()
        assertFalse(NativeTun2SocksBridge.isStarted())

        val originalFd = NativeTun2SocksSpikeVpnService.currentOriginalTunFileDescriptor()
            ?: throw AssertionError("expected the spike service's original TUN fd to still be held between cycles")

        var firstFailingCycle = -1
        var firstFailingReason = ""
        for (cycle in 2..STRESS_CYCLES) {
            val dupFd = ParcelFileDescriptor.dup(originalFd).detachFd()
            val startResult = NativeTun2SocksBridge.start(dupFd, 1500, "127.0.0.1:41999")
            if (startResult !is NativeBridgeResult.Ok) {
                firstFailingCycle = cycle
                firstFailingReason = "start: ${(startResult as? NativeBridgeResult.Failed)?.reason}"
                break
            }
            if (!NativeTun2SocksBridge.isStarted()) {
                firstFailingCycle = cycle
                firstFailingReason = "isStarted() false immediately after a reported-Ok start"
                break
            }

            // Periodically touch the Xray runtime too, so both Go runtimes
            // are actively exercised across the run, not merely mapped once.
            if (cycle % 10 == 0) {
                val stillNotRunning = !xray.isRunning
                if (!stillNotRunning) {
                    firstFailingCycle = cycle
                    firstFailingReason = "Xray isRunning unexpectedly true (never started) at cycle $cycle"
                    break
                }
            }

            val stopResult = NativeTun2SocksBridge.stop()
            if (stopResult !is NativeBridgeResult.Ok) {
                firstFailingCycle = cycle
                firstFailingReason = "stop: ${(stopResult as? NativeBridgeResult.Failed)?.reason}"
                break
            }
            if (NativeTun2SocksBridge.isStarted()) {
                firstFailingCycle = cycle
                firstFailingReason = "isStarted() true immediately after a reported-Ok stop"
                break
            }
        }

        Log.i(TAG, "stress run complete: cycles=$STRESS_CYCLES firstFailingCycle=$firstFailingCycle pid=$pid")
        assertEquals("first failing cycle (reason: $firstFailingReason)", -1, firstFailingCycle)

        // Xray runtime still healthy after 100 tun2socks cycles.
        assertFalse(xray.isRunning)

        // Final cleanup: close the real original TUN via the spike service.
        context.startService(Intent(context, NativeTun2SocksSpikeVpnService::class.java).setAction(NativeTun2SocksSpikeVpnService.ACTION_STOP))
        awaitIdle()
        assertFalse(NativeTun2SocksBridge.isStarted())
    }
}
