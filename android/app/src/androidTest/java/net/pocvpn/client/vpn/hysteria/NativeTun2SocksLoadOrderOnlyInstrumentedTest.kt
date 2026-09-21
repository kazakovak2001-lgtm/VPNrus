package net.pocvpn.client.vpn.hysteria

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3A Part F - minimal, TUN-independent same-process load-order proof.
 * Run ONE method at a time (`am instrument -e class ... -e method ...`)
 * against a freshly force-stopped process. Deliberately does not touch
 * [NativeTun2SocksSpikeVpnService] (a real TUN establish requires the
 * VpnService user-consent grant, an environment concern unrelated to the
 * question this test answers: does loading BOTH native Go runtimes into
 * one process, in either order, crash the process at all).
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksLoadOrderOnlyInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun xray_first_load_order() {
        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        assertFalse(NativeTun2SocksBridge.isStarted())

        assertFalse(xray.isRunning)
    }

    @Test
    fun tun2socks_first_load_order() {
        assertFalse(NativeTun2SocksBridge.isStarted())

        val xray = LibXrayCoreRuntime()
        xray.ensureCoreEnvInitialized(context)
        assertFalse(xray.isRunning)

        assertFalse(NativeTun2SocksBridge.isStarted())
    }
}
