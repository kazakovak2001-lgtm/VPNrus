package net.pocvpn.client.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8B3D unit-fix - narrow tests for isFreshHandshake() (VpnController.kt)
 * against CONCRETE millisecond values, deliberately not going through
 * FakeVpnTransport, to prove the seconds-vs-milliseconds distinction itself
 * rather than just the higher-level Connected/HandshakeFailed outcome.
 *
 * Real-world scale check: "now" in epoch MILLISECONDS is a 13-digit number
 * (~1.7e12 in 2026); the SAME instant in epoch SECONDS is only a 10-digit
 * number (~1.7e9) - about 1000x smaller. That gap is exactly what the
 * original bug collapsed by feeding a seconds-valued number in wherever
 * milliseconds were expected.
 */
class HandshakeUnitsTest {

    private val attemptStartEpochMillis = 1_777_000_000_000L // a realistic "now", epoch millis

    @Test
    fun `a real millis-shaped handshake at attempt start is fresh`() {
        assertTrue(isFreshHandshake(attemptStartEpochMillis, attemptStartEpochMillis))
    }

    @Test
    fun `a real millis-shaped handshake shortly after attempt start is fresh`() {
        assertTrue(isFreshHandshake(attemptStartEpochMillis + 1_500, attemptStartEpochMillis))
    }

    @Test
    fun `feeding the SECONDS-valued equivalent of attempt start (the original bug) is NOT fresh`() {
        // This is exactly what the pre-fix code produced: Backend.getLastHandshake()'s
        // raw seconds value (attemptStartEpochMillis / 1000) assigned directly as
        // if it were milliseconds - about 1000x too small, so it always compares
        // as enormously in the past relative to a real millis attempt-start.
        val buggySecondsTreatedAsMillis = attemptStartEpochMillis / 1000
        assertFalse(isFreshHandshake(buggySecondsTreatedAsMillis, attemptStartEpochMillis))
    }

    @Test
    fun `a genuinely old millis-shaped handshake, 26 minutes stale, is NOT fresh`() {
        val twentySixMinutesAgo = attemptStartEpochMillis - 26 * 60_000
        assertFalse(isFreshHandshake(twentySixMinutesAgo, attemptStartEpochMillis))
    }

    @Test
    fun `null (no handshake, including a normalized 0 or sentinel) is never fresh`() {
        assertFalse(isFreshHandshake(null, attemptStartEpochMillis))
    }

    @Test
    fun `zero is never treated as a valid handshake by the normalization contract`() {
        // AmneziaWgTransport.stats() normalizes 0 (and any non-positive value)
        // to null before it ever reaches isFreshHandshake - this test pins that
        // contract: a caller must never pass 0 through expecting it to mean
        // anything but "no handshake".
        assertFalse(isFreshHandshake(0L, attemptStartEpochMillis))
    }
}
