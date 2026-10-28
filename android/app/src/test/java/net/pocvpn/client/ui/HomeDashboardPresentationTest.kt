package net.pocvpn.client.ui

import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.VpnSessionHealth
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HomeDashboardPresentationTest {

    // --- duration -------------------------------------------------------

    @Test fun duration_formats_hh_mm_ss() {
        assertEquals("00:00:00", formatSessionDuration(0))
        assertEquals("00:00:59", formatSessionDuration(59_999))
        assertEquals("00:24:18", formatSessionDuration((24 * 60 + 18) * 1_000L))
        assertEquals("01:00:00", formatSessionDuration(3_600_000))
    }

    @Test fun duration_hours_are_not_capped_and_negative_clamps() {
        assertEquals("100:00:01", formatSessionDuration(100 * 3_600_000L + 1_000))
        assertEquals("00:00:00", formatSessionDuration(-5_000))
    }

    // --- bytes / rates --------------------------------------------------

    @Test fun bytes_boundaries() {
        assertEquals("0 B", formatByteCount(0))
        assertEquals("1023 B", formatByteCount(1023))
        assertEquals("1.0 KB", formatByteCount(1024))
        assertEquals("1.5 KB", formatByteCount(1536))
        assertEquals("1.0 MB", formatByteCount(1024L * 1024))
        assertEquals("128.4 MB", formatByteCount((128.4 * 1024 * 1024).toLong()))
        assertEquals("1.0 GB", formatByteCount(1024L * 1024 * 1024))
    }

    @Test fun bytes_rounding_carries_into_next_unit() {
        // 1023.96 KB must not print as "1024.0 KB".
        assertEquals("1.0 MB", formatByteCount((1023.96 * 1024).toLong()))
    }

    @Test fun bytes_negative_clamps_and_huge_values_stay_in_largest_unit() {
        assertEquals("0 B", formatByteCount(-1))
        assertTrue(formatByteCount(Long.MAX_VALUE).endsWith(" TB"))
    }

    @Test fun rates_use_per_second_units() {
        assertEquals("0 B/s", formatByteRate(0))
        assertEquals("512 B/s", formatByteRate(512))
        assertEquals("2.1 MB/s", formatByteRate((2.1 * 1024 * 1024).toLong()))
    }

    // --- protocol label -------------------------------------------------

    @Test fun every_transport_kind_has_a_nonblank_label() {
        TransportKind.values().forEach { assertTrue("$it", it.toHomeProtocolLabel().isNotBlank()) }
        assertEquals("REALITY + XHTTP", TransportKind.XRAY_REALITY_XHTTP.toHomeProtocolLabel())
        assertEquals("AmneziaWG", TransportKind.AMNEZIA_WG.toHomeProtocolLabel())
    }

    // --- protection authority -------------------------------------------

    @Test fun only_direct_and_relay_protected_count_as_protected() {
        assertTrue(VpnSessionHealth.DirectProtected.isProtected())
        assertTrue(VpnSessionHealth.RelayProtected.isProtected())
        assertFalse(VpnSessionHealth.Idle.isProtected())
        assertFalse(VpnSessionHealth.InProgress.isProtected())
        assertFalse(VpnSessionHealth.Reconnecting.isProtected())
        assertFalse(VpnSessionHealth.DataPlaneVerifying.isProtected())
        assertFalse(VpnSessionHealth.Failed("x").isProtected())
    }

    // --- uptime tracker -------------------------------------------------

    private var now = 1_000L
    private fun tracker() = SessionUptimeTracker { now }

    @Test fun starts_on_transition_into_protected_and_resets_on_leaving() {
        val t = tracker()
        t.onHealth(VpnSessionHealth.Idle)
        t.onHealth(VpnSessionHealth.InProgress)
        assertNull(t.startedAtMillis)
        now = 5_000
        assertTrue(t.onHealth(VpnSessionHealth.DirectProtected))
        assertEquals(5_000L, t.startedAtMillis)
        // Re-emission of the same protected state does not restart the timer.
        now = 9_000
        assertFalse(t.onHealth(VpnSessionHealth.DirectProtected))
        assertEquals(5_000L, t.startedAtMillis)
        // Direct -> Relay protected without a gap keeps the same period.
        assertFalse(t.onHealth(VpnSessionHealth.RelayProtected))
        assertEquals(5_000L, t.startedAtMillis)
        // Reconnecting resets; protected again starts a NEW period.
        assertTrue(t.onHealth(VpnSessionHealth.Reconnecting))
        assertNull(t.startedAtMillis)
        now = 20_000
        t.onHealth(VpnSessionHealth.DirectProtected)
        assertEquals(20_000L, t.startedAtMillis)
        t.onHealth(VpnSessionHealth.Idle)
        assertNull(t.startedAtMillis)
    }

    @Test fun verifying_and_failed_are_never_timed() {
        val t = tracker()
        t.onHealth(VpnSessionHealth.Idle)
        t.onHealth(VpnSessionHealth.DataPlaneVerifying)
        assertNull(t.startedAtMillis)
        t.onHealth(VpnSessionHealth.Failed("boom"))
        assertNull(t.startedAtMillis)
    }

    @Test fun first_observation_already_protected_has_unknown_start() {
        val t = tracker()
        t.onHealth(VpnSessionHealth.DirectProtected)
        assertNull(t.startedAtMillis)
        // A real transition afterwards is timed normally.
        t.onHealth(VpnSessionHealth.Reconnecting)
        now = 7_000
        t.onHealth(VpnSessionHealth.DirectProtected)
        assertEquals(7_000L, t.startedAtMillis)
    }

    @Test fun unreadable_clock_leaves_start_unknown_instead_of_guessing() {
        val t = SessionUptimeTracker { throw IllegalStateException("no clock") }
        t.onHealth(VpnSessionHealth.Idle)
        t.onHealth(VpnSessionHealth.DirectProtected)
        assertNull(t.startedAtMillis)
    }
}
