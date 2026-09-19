package net.pocvpn.client

import org.junit.Assert.assertFalse
import org.junit.Test

/**
 * Test F - the normal release/manual-activation build remains unchanged by
 * the Russia field-test build (see android/app/src/fieldTest). This module
 * runs against the `debug` variant's own compiled BuildConfig - if adding
 * the `fieldTest` build type had somehow flipped the shared default in
 * defaultConfig (android/app/build.gradle.kts), this compiled constant
 * would be `true` here too, since debug/release only ever read
 * defaultConfig's `false` (only the fieldTest build type block itself
 * overrides it to `true`, and this test target never compiles under that
 * build type).
 */
class FieldTestIsolationTest {

    @Test
    fun `F - normal build's FIELD_TEST_ONLY flag is false`() {
        assertFalse(BuildConfig.FIELD_TEST_ONLY)
    }

    @Test
    fun `F - normal build's application id has no field-test suffix`() {
        assertFalse(BuildConfig.APPLICATION_ID.endsWith(".fieldtest"))
    }
}
