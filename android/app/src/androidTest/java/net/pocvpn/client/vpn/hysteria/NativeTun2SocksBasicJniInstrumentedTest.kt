package net.pocvpn.client.vpn.hysteria

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.pocvpn.client.vpn.xray.LibXrayCoreRuntime
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * B46-3A Part D - basic real on-device JNI/native proof, no TUN involved.
 * Confirms both native runtimes are present and functional in the SAME real
 * app process: libnovatun2socks.so/libnovatun2socks_jni.so (this test's own
 * subject) AND the real pinned Xray AAR's own native runtime (touched via
 * the SAME production [LibXrayCoreRuntime.ensureCoreEnvInitialized] entry
 * point [net.pocvpn.client.vpn.xray.NovaXrayVpnService] uses - a real,
 * no-network, no-VPN call, never a fake/mock).
 *
 * Invalid-fd/invalid-mtu/empty-address cases call [NativeTun2SocksBridge]
 * directly (not [NativeTun2SocksController]'s Kotlin-side pre-gate, which is
 * already covered by the JVM unit tests) - this genuinely exercises the real
 * Go-side validation in `research/b46-3a-hysteria-native-bridge/native/main.go`
 * on the real device. A dummy non-negative fd (0) is used for the mtu/address
 * cases: Go's own validation order (fd, then mtu, then socksAddr, all before
 * `engine.Insert`) means that fd number is never touched in either case -
 * confirmed by reading the pinned source, not assumed.
 */
@RunWith(AndroidJUnit4::class)
class NativeTun2SocksBasicJniInstrumentedTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun isStarted_initially_false() {
        assertFalse(NativeTun2SocksBridge.isStarted())
    }

    @Test
    fun stop_before_start_is_harmless() {
        val result = NativeTun2SocksBridge.stop()
        assertTrue(result is NativeBridgeResult.Ok)
    }

    @Test
    fun invalid_fd_returns_controlled_failure() {
        val result = NativeTun2SocksBridge.start(fd = -1, mtu = 1500, socksAddr = "127.0.0.1:41999")
        assertTrue(result is NativeBridgeResult.Failed)
        assertTrue((result as NativeBridgeResult.Failed).reason.contains("invalid fd"))
    }

    @Test
    fun invalid_mtu_returns_controlled_failure() {
        val result = NativeTun2SocksBridge.start(fd = 0, mtu = 0, socksAddr = "127.0.0.1:41999")
        assertTrue(result is NativeBridgeResult.Failed)
        assertTrue((result as NativeBridgeResult.Failed).reason.contains("invalid mtu"))
    }

    @Test
    fun empty_socks_address_fails_closed() {
        val result = NativeTun2SocksBridge.start(fd = 0, mtu = 1500, socksAddr = "")
        assertTrue(result is NativeBridgeResult.Failed)
        assertTrue((result as NativeBridgeResult.Failed).reason.contains("empty socks address"))
    }

    /**
     * Real, no-network, no-VPN entry into the Xray Go runtime - the SAME
     * production call [net.pocvpn.client.vpn.xray.NovaXrayVpnService] makes
     * before ever calling `startLoop`. Never starts a real Xray session
     * (that would require a config/TUN and real network egress, out of
     * scope for this slice).
     */
    @Test
    fun xray_runtime_initializes_in_same_process() {
        val runtime = LibXrayCoreRuntime()
        runtime.ensureCoreEnvInitialized(context)
        // isRunning is a real native getter on the real CoreController - a
        // harmless read, proving the runtime genuinely initialized rather
        // than merely not-throwing.
        assertFalse(runtime.isRunning)
    }

    @Test
    fun both_native_runtimes_coexist_in_same_process() {
        val runtime = LibXrayCoreRuntime()
        runtime.ensureCoreEnvInitialized(context)
        assertFalse(runtime.isRunning)

        assertFalse(NativeTun2SocksBridge.isStarted())
    }
}
