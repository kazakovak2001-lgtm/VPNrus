package net.pocvpn.client.debug.b45a

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B45A - SPIKE ONLY. Validates [B45ADataPlaneConfig.resolve]'s own
 * validation logic (Phase 1, round 6) - never asserts on or prints the
 * actual resolved key value itself, only its VALIDITY, since whatever
 * `b45a-dataplane.properties` this checkout happens to have (real,
 * disposable, or absent) flows straight into `BuildConfig` at compile
 * time.
 */
class B45ADataPlaneConfigTest {

    @Test
    fun `resolve always returns Valid, never Invalid, for both the fallback and any configured key`() {
        // Whatever this checkout's BuildConfig.B45A_TEST_SERVER_KEY is
        // (blank -> falls back to SPIKE_FAKE_PSK, itself already covered
        // by B45AFakeKeyFormatTest; or a real properties-file value) -
        // resolve() must never surface an Invalid result for a
        // correctly-generated key. A failure here means either this
        // checkout's b45a-dataplane.properties has a malformed key, or the
        // fallback itself regressed.
        val result = B45ADataPlaneConfig.resolve()

        assertTrue("resolve() returned Invalid - see B45ADataPlaneConfig's own reason string", result is B45ADataPlaneConfig.Result.Valid)
    }

    @Test
    fun `resolved method is the AEAD-2022 method this spike is pinned to`() {
        val result = B45ADataPlaneConfig.resolve() as B45ADataPlaneConfig.Result.Valid

        assertEquals("2022-blake3-aes-256-gcm", result.method)
    }

    @Test
    fun `resolved server address is host colon port shaped`() {
        val result = B45ADataPlaneConfig.resolve() as B45ADataPlaneConfig.Result.Valid

        val parts = result.serverAddr.split(":")
        assertEquals(2, parts.size)
        assertTrue(parts[1].toIntOrNull() != null)
    }
}
