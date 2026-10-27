package net.pocvpn.client.ui.screens

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FieldTestOptionsTest {
    @Test
    fun `release offers full and monitor modes but no local copy`() {
        val options = FieldTestOptions.forBuild(isDebugBuild = false)
        assertTrue(options.allModes)
        assertFalse(options.canSaveLocally)
    }

    @Test
    fun `debug offers every mode and the local copy`() {
        val options = FieldTestOptions.forBuild(isDebugBuild = true)
        assertTrue(options.allModes)
        assertTrue(options.canSaveLocally)
    }
}
