package net.pocvpn.client.smartconnect

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class DebugPathOverrideReleaseTest {
    @Test
    fun `release cannot force a relay path and says so`() {
        assertFalse(DebugPathOverride.isAvailable)
        DebugPathOverride.forceRelayedVia("stockholm-ingress-1")
        assertNull(DebugPathOverride.lastAppliedAttemptKeys())
        assertNull(DebugPathOverride.statusLine())
    }
}
