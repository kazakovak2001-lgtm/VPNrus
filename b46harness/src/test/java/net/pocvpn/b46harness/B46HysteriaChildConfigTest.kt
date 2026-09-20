package net.pocvpn.b46harness

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B46-2P - the config parser/holder must never expose [B46HysteriaChildConfig.auth]
 * (or [B46HysteriaChildConfig.obfsSalamander]) via `toString()`/logging, per
 * the task's own secret-handling requirement.
 */
class B46HysteriaChildConfigTest {

    private val secretAuth = "super-secret-test-auth-value-should-never-appear"
    private val secretObfs = "super-secret-obfs-value-should-never-appear"

    @Test
    fun `toString never contains the auth secret`() {
        val config = testConfig().copy(auth = secretAuth)
        assertFalse(config.toString().contains(secretAuth))
    }

    @Test
    fun `toString never contains the obfsSalamander secret`() {
        val config = testConfig().copy(obfsSalamander = secretObfs)
        assertFalse(config.toString().contains(secretObfs))
    }

    @Test
    fun `redactedSummary never contains auth or obfsSalamander but reports whether they are set`() {
        val config = testConfig().copy(auth = secretAuth, obfsSalamander = secretObfs)
        val summary = config.redactedSummary()

        assertFalse(summary.contains(secretAuth))
        assertFalse(summary.contains(secretObfs))
        assertTrue(summary.contains("authSet=true"))
        assertTrue(summary.contains("obfsSet=true"))
    }

    @Test
    fun `string interpolation of the config (a common accidental-log pattern) is also redacted`() {
        val config = testConfig().copy(auth = secretAuth)
        val interpolated = "config=$config"
        assertFalse(interpolated.contains(secretAuth))
    }

    @Test
    fun `toJson DOES include auth - it is the payload the child reads, not a log line`() {
        // Deliberate: toJson() feeds writeChildConfigFile(), the ONE place
        // the secret is allowed to exist at rest (mode 600, app-private,
        // deleted on stop) - never confused with toString()/logging above.
        val config = testConfig().copy(auth = secretAuth)
        assertTrue(config.toJson().contains(secretAuth))
    }

    @Test
    fun `toJson escapes embedded quotes and backslashes so the child's JSON parser never breaks`() {
        val config = testConfig().copy(auth = "has\"quote\\backslash")
        val json = config.toJson()
        assertTrue(json.contains("has\\\"quote\\\\backslash"))
    }
}
