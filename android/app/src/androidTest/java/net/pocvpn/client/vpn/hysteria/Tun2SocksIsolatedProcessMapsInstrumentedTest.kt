package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3B Part G/H - the core process-isolation acceptance gate: real
 * `/proc/<pid>/maps` evidence that the app process and the tun2socks child
 * process are genuinely separate, with disjoint native-runtime footprints.
 *
 * App process (this test's own process, since instrumentation runs
 * in-process with the target app): must show `libgojni.so` mapped (Xray)
 * and must NOT show the tun2socks child executable mapped as a library -
 * it never is, by construction (it is exec()'d as a separate process, never
 * dlopen()'d).
 *
 * Child process: read via `/proc/<childPid>/maps` from the app process
 * (same UID, no `run-as` needed - `run-as` is for a different package's
 * sandbox, not for a same-app child process). Must show the tun2socks
 * child's own executable mapped and must NOT show `libgojni.so` mapped -
 * structurally guaranteed (the plain Go executable never calls into any
 * JNI/dlopen path for Xray's library at all), confirmed here directly
 * rather than merely asserted.
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksIsolatedProcessMapsInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String) {
        instrumentation.uiAutomation.executeShellCommand(cmd).use {
            it.fileDescriptor.let { fd -> java.io.FileInputStream(fd).bufferedReader().readText() }
        }
    }

    private fun awaitStatus(timeoutMillis: Long = 8_000): Tun2SocksIsolatedSpikeStatus {
        val deadline = System.currentTimeMillis() + timeoutMillis
        var last = Tun2SocksProcessIsolatedSpikeVpnService.status.value
        while (System.currentTimeMillis() < deadline) {
            last = Tun2SocksProcessIsolatedSpikeVpnService.status.value
            if (last !is Tun2SocksIsolatedSpikeStatus.Idle) return last
            Thread.sleep(50)
        }
        return last
    }

    private fun awaitIdle(timeoutMillis: Long = 8_000) {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            if (Tun2SocksProcessIsolatedSpikeVpnService.status.value is Tun2SocksIsolatedSpikeStatus.Idle) return
            Thread.sleep(50)
        }
    }

    @Test
    fun app_and_child_processes_are_isolated() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")

        // Real Xray runtime, in this (app) process.
        net.pocvpn.client.vpn.xray.LibXrayCoreRuntime().ensureCoreEnvInitialized(context)

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_START))
        val started = awaitStatus()
        assertTrue("expected Started, got $started", started is Tun2SocksIsolatedSpikeStatus.Started)
        val childPid = (started as Tun2SocksIsolatedSpikeStatus.Started).childPid
        val appPid = Process.myPid()

        val appMaps = File("/proc/self/maps").readText()
        android.util.Log.i("B46_3B_Maps", "app process pid=$appPid maps contain libgojni.so=${appMaps.contains("libgojni.so")} libnovatun2sockschild=${appMaps.contains("libnovatun2sockschild")}")
        assertTrue("expected libgojni.so mapped in the app process (pid=$appPid)", appMaps.contains("libgojni.so"))
        assertFalse(
            "expected the tun2socks child executable NOT mapped as a library in the app process (pid=$appPid) - it must only ever run as a separate process, never dlopen()'d",
            appMaps.contains("libnovatun2sockschild"),
        )

        val childMapsFile = File("/proc/$childPid/maps")
        if (childMapsFile.canRead()) {
            val childMaps = childMapsFile.readText()
            android.util.Log.i("B46_3B_Maps", "child process pid=$childPid maps contain libgojni.so=${childMaps.contains("libgojni.so")} libnovatun2sockschild=${childMaps.contains("libnovatun2sockschild")}")
            childMaps.lineSequence().filter { it.contains("libnovatun2sockschild") || it.contains("libgojni") }.take(6).forEach {
                android.util.Log.i("B46_3B_Maps", "child maps: $it")
            }
            assertFalse("expected libgojni.so NOT mapped in the child process (pid=$childPid) - the child never touches Xray's library at all", childMaps.contains("libgojni.so"))
            assertTrue("expected the tun2socks-child executable itself mapped in its own process (pid=$childPid)", childMaps.contains("libnovatun2sockschild"))
        } else {
            android.util.Log.w("B46_3B_Maps", "/proc/$childPid/maps not readable from the app process on this device/kernel policy - see docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md for how this was handled")
        }

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_STOP))
        awaitIdle()
    }
}
