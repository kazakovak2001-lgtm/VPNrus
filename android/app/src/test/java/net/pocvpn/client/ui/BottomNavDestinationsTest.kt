package net.pocvpn.client.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class BottomNavDestinationsTest {
    @Test fun release_has_no_diagnostics_tab() {
        val tabs = bottomNavDestinations(isDebugBuild = false)
        assertEquals(listOf(NavDestination.VPN, NavDestination.SERVERS, NavDestination.SETTINGS), tabs)
        assertFalse(NavDestination.DIAGNOSTICS in tabs)
    }

    @Test fun debug_has_all_four_in_order() {
        assertEquals(
            listOf(NavDestination.VPN, NavDestination.SERVERS, NavDestination.DIAGNOSTICS, NavDestination.SETTINGS),
            bottomNavDestinations(isDebugBuild = true),
        )
    }
}
