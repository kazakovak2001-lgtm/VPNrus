package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3B lifecycle-hardening pass (Gap 3, parent-death/orphan test) -
 * purpose-built harness, NOT a self-contained pass/fail test. A real
 * parent-death test cannot assert post-death evidence from WITHIN the
 * process that is about to die (the task's own instruction: "Do not use
 * this test if Android instrumentation teardown itself makes the evidence
 * ambiguous"). This class's only job is to start a REAL session (real TUN,
 * real child process, real `B46_3B_CHILD_STARTED: pid=...` log line) and
 * then simply END - `am instrument` completion itself triggers
 * `ActivityManager` killing this app's own process ("Killing ... due to
 * finished inst" - confirmed in this project's own prior logcat evidence),
 * which IS a real, externally-observable app-process-death event. The
 * actual pass/fail check (does the child disappear afterward) is done from
 * OUTSIDE this process, via plain `adb shell` commands run by the
 * orchestrating operator/script AFTER this instrumentation call returns -
 * see docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md's own Part 3-B for the
 * exact commands and real result.
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksIsolatedParentDeathHarnessInstrumentedTest {

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

    @Test
    fun start_and_leave_running_for_external_parent_death_check() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_START))
        val started = awaitStatus()
        assertTrue("expected Started, got $started", started is Tun2SocksIsolatedSpikeStatus.Started)

        // Deliberately no stop() here, no cleanup - this test's own process
        // (and the child it just spawned) are left running on purpose. The
        // real parent-death check happens from OUTSIDE, after this
        // instrumentation call returns.
    }
}
