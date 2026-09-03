package net.pocvpn.client.diagnostics.support

import net.pocvpn.client.network.NetworkType
import net.pocvpn.client.smartconnect.RestrictionClass
import net.pocvpn.client.vpn.config.GatewaySelectionMode
import net.pocvpn.client.vpn.policy.RoutingMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** B29 (task D/K) - bounded retention/eviction: last N sessions, oldest-first eviction, no unlimited growth. */
class DiagnosticSessionStoreTest {

    private fun session(id: String) = DiagnosticSession(
        sessionId = id,
        startedAtEpochMillis = 0L,
        endedAtEpochMillis = 1L,
        appVersionName = "1.0",
        appVersionCode = 1L,
        networkType = NetworkType.WIFI,
        networkValidatedInternet = true,
        networkCaptivePortal = false,
        networkIpv4Available = true,
        networkIpv6Available = false,
        networkFingerprintId = null,
        rawRestrictionClass = RestrictionClass.UNKNOWN,
        stabilizedRestrictionClass = RestrictionClass.UNKNOWN,
        routingMode = RoutingMode.FULL_VPN,
        gatewaySelectionMode = GatewaySelectionMode.AUTO,
        selectedPathKind = PathKind.DIRECT,
        selectedTransportKind = null,
        events = emptyList(),
        outcome = DiagnosticOutcome.PROTECTED,
        failureReason = null,
    )

    @Test
    fun `recent returns an empty list when nothing was ever appended`() {
        assertTrue(InMemoryDiagnosticSessionStore().recent().isEmpty())
    }

    @Test
    fun `appended sessions are returned most-recent-first`() {
        val store = InMemoryDiagnosticSessionStore()
        store.append(session("a"))
        store.append(session("b"))
        store.append(session("c"))
        assertEquals(listOf("c", "b", "a"), store.recent().map { it.sessionId })
    }

    @Test
    fun `retention is bounded - oldest session is evicted first once the cap is exceeded`() {
        val store = InMemoryDiagnosticSessionStore()
        val total = DiagnosticSessionStore.MAX_RETAINED_SESSIONS + 3
        repeat(total) { i -> store.append(session("s$i")) }
        val retained = store.recent()
        assertEquals(DiagnosticSessionStore.MAX_RETAINED_SESSIONS, retained.size)
        // The oldest 3 (s0, s1, s2) must be gone; the newest must be present.
        assertTrue(retained.none { it.sessionId in setOf("s0", "s1", "s2") })
        assertEquals("s${total - 1}", retained.first().sessionId)
    }

    @Test
    fun `clear removes every retained session`() {
        val store = InMemoryDiagnosticSessionStore()
        store.append(session("a"))
        store.append(session("b"))
        store.clear()
        assertTrue(store.recent().isEmpty())
    }
}
