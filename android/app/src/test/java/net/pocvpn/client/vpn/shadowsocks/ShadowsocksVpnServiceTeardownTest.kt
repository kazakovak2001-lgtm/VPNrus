package net.pocvpn.client.vpn.shadowsocks

import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * B45B-4P fix - the other half of the physical disconnect/ownership bug:
 * [ShadowsocksVpnService.teardown] used to set its companion `status` flow
 * straight to `null` on a genuine stop. [ShadowsocksTransport]'s own status
 * collector explicitly ignores a `null` status, so a real, successful
 * teardown never reached it - proves the real fix (publishing a genuine
 * [ShadowsocksRuntimePhase.STOPPED] instead) actually reaches the shared
 * status flow real callers observe.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ShadowsocksVpnServiceTeardownTest {

    @Test
    fun `ACTION_STOP publishes a real STOPPED status, never null - the exact physical bug`() {
        val service = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        // Run teardown's dispatch synchronously for a deterministic
        // assertion - production keeps the real Dispatchers.Default.
        service.teardownDispatcher = Dispatchers.Unconfined

        val intent = android.content.Intent(ShadowsocksVpnService.ACTION_STOP)
        service.onStartCommand(intent, 0, 1)

        val status = ShadowsocksVpnService.status.value
        assertNotNull("teardown must publish a real status, never null", status)
        assertEquals(ShadowsocksRuntimePhase.STOPPED, status!!.phase)
        // Never carries any leftover FAILED/other reason on a genuine stop.
        assertEquals(null, status.error)
    }

    @Test
    fun `ACTION_STOP on a never-started service is a harmless no-op, still publishes STOPPED`() {
        val service = Robolectric.buildService(ShadowsocksVpnService::class.java).create().get()
        service.teardownDispatcher = Dispatchers.Unconfined

        service.onStartCommand(android.content.Intent(ShadowsocksVpnService.ACTION_STOP), 0, 1)
        service.onStartCommand(android.content.Intent(ShadowsocksVpnService.ACTION_STOP), 0, 2)

        assertEquals(ShadowsocksRuntimePhase.STOPPED, ShadowsocksVpnService.status.value?.phase)
    }
}
