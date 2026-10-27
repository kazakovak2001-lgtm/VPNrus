package net.pocvpn.client.smartconnect

import org.junit.Assert.assertTrue
import org.junit.Test

class DebugPathOverrideAvailabilityTest {
    @Test
    fun `debug can force a relay path`() {
        assertTrue(DebugPathOverride.isAvailable)
    }
}
