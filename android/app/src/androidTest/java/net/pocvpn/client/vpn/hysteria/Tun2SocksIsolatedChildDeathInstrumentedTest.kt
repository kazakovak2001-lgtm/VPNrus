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
 * B46-3B lifecycle-hardening pass (Gap 1 / "child death V2") - controlled
 * child death, now proving AUTOMATIC lifecycle ownership rather than only
 * "the app survives and a later explicit stop happens to work" (the
 * original, insufficient version of this test - see
 * docs/B46_3B_HYSTERIA_PROCESS_ISOLATION.md's own lifecycle-audit
 * finding). Deliberately does NOT call `ACTION_STOP` immediately after
 * killing the child - it waits for [Tun2SocksChildRuntime]'s own
 * `onExit`-driven unexpected-death detection to run, then asserts the
 * service reached a terminal [Tun2SocksIsolatedSpikeStatus.Failed] state,
 * the TUN interface is gone, and the control socket file is gone - all
 * WITHOUT any caller ever issuing an explicit stop. `ACTION_STOP` is only
 * exercised at the very end, as a pure idempotency check.
 */
@RunWith(AndroidJUnit4::class)
class Tun2SocksIsolatedChildDeathInstrumentedTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun shell(cmd: String): String =
        instrumentation.uiAutomation.executeShellCommand(cmd).use {
            it.fileDescriptor.let { fd -> java.io.FileInputStream(fd).bufferedReader().readText() }
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

    private fun awaitFailedStatus(timeoutMillis: Long = 8_000): Tun2SocksIsolatedSpikeStatus? {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (System.currentTimeMillis() < deadline) {
            val current = Tun2SocksProcessIsolatedSpikeVpnService.status.value
            if (current is Tun2SocksIsolatedSpikeStatus.Failed) return current
            Thread.sleep(50)
        }
        return null
    }

    @Test
    fun killing_the_child_is_automatically_detected_tears_down_tun_and_reaches_a_terminal_failed_state() {
        shell("appops set ${context.packageName} ACTIVATE_VPN allow")

        context.startService(Intent(context, Tun2SocksProcessIsolatedSpikeVpnService::class.java).setAction(Tun2SocksProcessIsolatedSpikeVpnService.ACTION_START))
        val started = awaitStatus()
        assertTrue("expected Started, got $started", started is Tun2SocksIsolatedSpikeStatus.Started)
        val childPid = (started as Tun2SocksIsolatedSpikeStatus.Started).childPid
        val appPidBefore = Process.myPid()
        assertTrue("expected /proc/$childPid to exist right after a reported-Started ack", File("/proc/$childPid").exists())

        val controlSocketFile = File(context.filesDir, TUN2SOCKS_CONTROL_SOCKET_FILENAME)
        assertTrue("expected the control socket file to exist while a session is running", controlSocketFile.exists())

        // Deliberate, controlled kill - SIGKILL (9), same UID, no root needed.
        Process.sendSignal(childPid, 9)

        // 1. Child is genuinely gone (kernel-level fact).
        val childGoneDeadline = System.currentTimeMillis() + 5_000
        var childGone = false
        while (System.currentTimeMillis() < childGoneDeadline) {
            if (!File("/proc/$childPid").exists()) {
                childGone = true
                break
            }
            Thread.sleep(50)
        }
        assertTrue("expected the child process to actually be gone after SIGKILL", childGone)

        // 2. AUTOMATIC detection: the service must reach Failed on its own -
        // no ACTION_STOP has been sent yet.
        val failed = awaitFailedStatus()
        assertTrue("expected the service to automatically reach a terminal Failed status after the child died, got ${Tun2SocksProcessIsolatedSpikeVpnService.status.value}", failed != null)

        // 3. The TUN interface must be torn down automatically too - real
        // kernel-level evidence, not just the Kotlin-side status field.
        val tunGoneDeadline = System.currentTimeMillis() + 5_000
        var tunGone = false
        while (System.currentTimeMillis() < tunGoneDeadline) {
            if (!shell("ip link show").contains("tun0")) {
                tunGone = true
                break
            }
            Thread.sleep(100)
        }
        assertTrue("expected the TUN interface to be torn down automatically after the child died unexpectedly", tunGone)

        // 4. The control socket artifact must be cleaned up automatically too.
        assertFalse("expected the control socket file to be deleted automatically after the child died unexpectedly", controlSocketFile.exists())

        // 5. The app process itself must be completely unaffected throughout.
        assertTrue("app process must survive the child's death unaffected", Process.myPid() == appPidBefore)

        // 6. Finally, a subsequent explicit stop must still be a harmless
        // no-op (pure idempotency check - the real teardown already
        // happened automatically above).
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
        assertTrue("expected the idempotency-check stop to still reach Idle", reachedIdle)
        assertTrue("app process must still be alive and responsive", Process.myPid() == appPidBefore)
    }
}
