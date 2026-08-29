package net.pocvpn.client.vpn.xray

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure state-machine tests for the exact ordering NovaXrayVpnService relies
 * on - "duplicate start creates no duplicate core", "stop before start is a
 * no-op", "a second teardown call is a no-op" (so stopLoop()/tun-close only
 * ever run once per successful start). See XrayServiceLifecycleGate's own
 * docs for why this is tested here rather than against the real
 * android.net.VpnService (this project has no Robolectric dependency).
 */
class XrayServiceLifecycleGateTest {

    @Test
    fun `a fresh gate allows the first start to proceed`() {
        val gate = XrayServiceLifecycleGate()
        assertEquals(XrayServiceStartDecision.PROCEED, gate.tryBeginStart())
    }

    @Test
    fun `a second start while the first is still in flight is ignored - no duplicate core`() {
        val gate = XrayServiceLifecycleGate()
        assertEquals(XrayServiceStartDecision.PROCEED, gate.tryBeginStart())

        // First start's establish()/startLoop() has not finished yet (endStart not called).
        assertEquals(XrayServiceStartDecision.IGNORE_START_IN_FLIGHT, gate.tryBeginStart())
    }

    @Test
    fun `a start while already running is ignored - no duplicate core`() {
        val gate = XrayServiceLifecycleGate()
        gate.tryBeginStart()
        gate.endStart(success = true)
        assertTrue(gate.isRunning)

        assertEquals(XrayServiceStartDecision.IGNORE_ALREADY_RUNNING, gate.tryBeginStart())
    }

    @Test
    fun `a failed start does not leave isRunning true, and a new start may proceed`() {
        val gate = XrayServiceLifecycleGate()
        gate.tryBeginStart()
        gate.endStart(success = false)

        assertFalse(gate.isRunning)
        assertEquals(XrayServiceStartDecision.PROCEED, gate.tryBeginStart())
    }

    @Test
    fun `stop before start is a no-op`() {
        val gate = XrayServiceLifecycleGate()
        assertFalse(gate.tryBeginTeardown())
    }

    @Test
    fun `teardown after a successful start proceeds exactly once`() {
        val gate = XrayServiceLifecycleGate()
        gate.tryBeginStart()
        gate.endStart(success = true)

        assertTrue(gate.tryBeginTeardown())
        assertFalse(gate.isRunning)
    }

    @Test
    fun `a second teardown call after an explicit stop is a no-op - service destruction cleans resources exactly once`() {
        val gate = XrayServiceLifecycleGate()
        gate.tryBeginStart()
        gate.endStart(success = true)

        assertTrue(gate.tryBeginTeardown())
        // e.g. onDestroy() running after ACTION_STOP already tore everything down.
        assertFalse(gate.tryBeginTeardown())
    }

    @Test
    fun `after teardown, a new start may proceed again`() {
        val gate = XrayServiceLifecycleGate()
        gate.tryBeginStart()
        gate.endStart(success = true)
        gate.tryBeginTeardown()

        assertEquals(XrayServiceStartDecision.PROCEED, gate.tryBeginStart())
    }
}
