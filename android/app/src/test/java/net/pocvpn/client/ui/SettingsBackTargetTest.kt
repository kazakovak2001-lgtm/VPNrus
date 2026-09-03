package net.pocvpn.client.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * B30A - physical-validation fix. Proves the settingsRoute transition
 * Android's system Back button now drives (via BackHandler in AppRoot)
 * matches each screen's own "back arrow" onBack lambda exactly: AppSelector
 * steps back to Settings, and Settings steps back to Home (null) - never
 * straight to Activity-finish, which is what exited the app to the launcher
 * on physical devices before this fix.
 */
class SettingsBackTargetTest {

    @Test
    fun `back from AppSelector returns to Settings, not Home`() {
        assertEquals(SettingsRoute.Settings, settingsBackTarget(SettingsRoute.AppSelector))
    }

    @Test
    fun `back from Settings returns to Home, not Activity-finish`() {
        assertNull(settingsBackTarget(SettingsRoute.Settings))
    }

    @Test
    fun `back while already on Home is a no-op`() {
        assertNull(settingsBackTarget(null))
    }
}
