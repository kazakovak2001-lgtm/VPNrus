package net.pocvpn.client.vpn.hysteria

import android.content.Intent
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3B - controlled child death: while a real session is running,
 * deliberately kill the tun2socks child process (SIGKILL, via
 * [Process.sendSignal] - a same-UID signal, no `run-as`/root needed) and
 * confirm the app process itself survives unaffected, and that a normal
 * `ACTION_STOP` afterwards is still a harmless no-op (the child is already
 * gone; nothing double-frees or hangs).
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksIsolatedChildDeathInstrumentedTest {

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
    fun killing_the_child_does_not_crash_the_app_process() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_START))
        val started = awaitStatus()
        assertTrue("expected Started, got $started", started is Tun2SocksIsolatedSpikeStatus.Started)
        val childPid = (started as Tun2SocksIsolatedSpikeStatus.Started).childPid
        val appPidBefore = Process.myPid()
        assertTrue("expected /proc/$childPid to exist right after a reported-Started ack", File("/proc/$childPid").exists())

        // Deliberate, controlled kill - SIGKILL (9), same UID, no root needed.
        Process.sendSignal(childPid, 9)

        val deadline = System.currentTimeMillis() + 5_000
        var childGone = false
        while (System.currentTimeMillis() < deadline) {
            if (!File("/proc/$childPid").exists()) {
                childGone = true
                break
            }
            Thread.sleep(50)
        }
        assertTrue("expected the child process to actually be gone after SIGKILL", childGone)

        // The app process itself must be completely unaffected - same pid,
        // still able to do ordinary work (a plain assertion running at all,
        // right after the kill, is itself part of the proof).
        assertTrue("app process must survive the child's death unaffected", Process.myPid() == appPidBefore)

        // A subsequent stop must still be harmless (idempotent cleanup, no
        // hang, no crash) even though the child is already dead.
        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_STOP))
        val idleDeadline = System.currentTimeMillis() + 8_000
        var reachedIdle = false
        while (System.currentTimeMillis() < idleDeadline) {
            if (Tun2SocksProcessIsolatedSpikeVpnService.status.value is Tun2SocksIsolatedSpikeStatus.Idle) {
                reachedIdle = true
                break
            }
            Thread.sleep(50)
        }
        assertTrue("expected stop-after-child-death to still reach Idle", reachedIdle)
        assertTrue("app process must still be alive and responsive", Process.myPid() == appPidBefore)
    }
}
