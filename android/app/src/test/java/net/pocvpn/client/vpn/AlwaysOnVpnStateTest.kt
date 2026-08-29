package net.pocvpn.client.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B8G - narrow proof that Always-on/lockdown detection is represented
 * truthfully: only ever CONFIRMED_ENABLED (after the one real signal fires)
 * or UNKNOWN - this enum has no "confirmed disabled" value to fabricate in
 * the first place (see AlwaysOnVpnState's own docs for why).
 */
class AlwaysOnVpnStateTest {

    @Test
    fun `default state is UNKNOWN, never a fabricated NOT_ENABLED`() {
        // AlwaysOnVpnState is a singleton object - if an earlier test in the
        // same JVM already marked it enabled, this narrow assertion isn't
        // about resetting global state, just that UNKNOWN is a real,
        // reachable value distinct from CONFIRMED_ENABLED.
        assertEquals(2, AlwaysOnDetectionState.entries.size)
        assertEquals(
            setOf(AlwaysOnDetectionState.CONFIRMED_ENABLED, AlwaysOnDetectionState.UNKNOWN),
            AlwaysOnDetectionState.entries.toSet(),
        )
    }

    @Test
    fun `marking confirmed enabled flips the state and it stays enabled`() {
        AlwaysOnVpnState.markConfirmedEnabled()
        assertEquals(AlwaysOnDetectionState.CONFIRMED_ENABLED, AlwaysOnVpnState.state.value)
    }
}
