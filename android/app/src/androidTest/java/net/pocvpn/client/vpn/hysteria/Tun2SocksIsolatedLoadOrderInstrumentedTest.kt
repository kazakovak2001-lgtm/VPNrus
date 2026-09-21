package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3B Part F/load-order regression - run ONE method at a time
 * (`am instrument -e class ... -e method ...`) against a freshly
 * force-stopped process, mirroring B46-3A's own load-order test structure
 * but proving the OPPOSITE result is now true: since the tun2socks Go
 * runtime never loads into this process at all (it always runs in a
 * separate OS process spawned by [Tun2SocksProcessIsolatedSpikeVpnService]),
 * BOTH orders must survive - there is no shared in-process Go runtime state
 * left to corrupt.
 *
 * Two clean cycles per ordering, per the task's own "two independent
 * cycles ... unless a failure occurs" bound - not dozens of retries.
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksIsolatedLoadOrderInstrumentedTest {

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

    private fun oneRealCycle(): Int {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")
        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_START))
        val started = awaitStatus()
        assertTrue("expected Started, got $started", started is Tun2SocksIsolatedSpikeStatus.Started)
        val childPid = (started as Tun2SocksIsolatedSpikeStatus.Started).childPid
        val appPid = Process.myPid()
        assertNotEquals("child must run in a DIFFERENT OS process than the app", appPid, childPid)
        assertTrue("child pid must be a real positive pid, was $childPid", childPid > 0)

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_STOP))
        awaitIdle()
        return childPid
    }

    @Test
    fun xray_first_then_child_two_cycles() {
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        val pid1 = oneRealCycle()
        assertFalse("Xray must remain healthy after cycle 1", xray.isRunning)
        val pid2 = oneRealCycle()
        assertFalse("Xray must remain healthy after cycle 2", xray.isRunning)
        assertNotEquals("two cycles should spawn genuinely distinct child processes", pid1, pid2)
    }

    @Test
    fun child_first_then_xray_two_cycles() {
        val pid1 = oneRealCycle()

        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        val pid2 = oneRealCycle()
        assertFalse("Xray must remain healthy after a second child cycle", xray.isRunning)
        assertNotEquals("two cycles should spawn genuinely distinct child processes", pid1, pid2)
    }
}
