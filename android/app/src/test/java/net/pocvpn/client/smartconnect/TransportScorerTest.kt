package net.pocvpn.client.smartconnect

import net.pocvpn.client.transport.TransportCapabilities
import net.pocvpn.client.transport.TransportFailureCategory
import net.pocvpn.client.transport.TransportHealth
import net.pocvpn.client.transport.TransportHealthState
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.transport.TransportMaturity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TransportScorerTest {

    private fun health(state: TransportHealthState) = TransportHealth(state = state, failureCategory = TransportFailureCategory.NONE)

    @Test
    fun `a NOT_IMPLEMENTED transport always scores lowest, regardless of health`() {
        val score = TransportScorer.score(TransportKind.QUIC, TransportCapabilities.notImplemented(), health(TransportHealthState.HEALTHY))
        assertEquals(Int.MIN_VALUE, score)
    }

    @Test
    fun `a real transport with HEALTHY state outscores the same transport DEGRADED or UNREACHABLE`() {
        val caps = TransportCapabilities.amneziaWg()
        val healthy = TransportScorer.score(TransportKind.AMNEZIA_WG, caps, health(TransportHealthState.HEALTHY))
        val degraded = TransportScorer.score(TransportKind.AMNEZIA_WG, caps, health(TransportHealthState.DEGRADED))
        val unreachable = TransportScorer.score(TransportKind.AMNEZIA_WG, caps, health(TransportHealthState.UNREACHABLE))
        assertTrue(healthy > degraded)
        assertTrue(degraded > unreachable)
    }

    @Test
    fun `UNKNOWN health (never observed) outscores a confirmed DEGRADED or UNREACHABLE state - never punished for lack of evidence`() {
        val caps = TransportCapabilities.amneziaWg()
        val unknown = TransportScorer.score(TransportKind.AMNEZIA_WG, caps, health(TransportHealthState.UNKNOWN))
        val degraded = TransportScorer.score(TransportKind.AMNEZIA_WG, caps, health(TransportHealthState.DEGRADED))
        assertTrue(unknown > degraded)
    }

    @Test
    fun `real recent health dominates maturity - a DEGRADED stable transport never outranks a HEALTHY experimental one`() {
        val stableDegraded = TransportScorer.score(
            TransportKind.AMNEZIA_WG,
            TransportCapabilities.amneziaWg().copy(maturity = TransportMaturity.STABLE),
            health(TransportHealthState.DEGRADED),
        )
        val experimentalHealthy = TransportScorer.score(
            TransportKind.XRAY_REALITY,
            TransportCapabilities.xrayRealityAdapterShell(),
            health(TransportHealthState.HEALTHY),
        )
        assertTrue(experimentalHealthy > stableDegraded)
    }

    @Test
    fun `rank() orders by score descending, ties broken by TransportKind's own declared enum order`() {
        val entries = mapOf(
            TransportKind.QUIC to (TransportCapabilities.notImplemented() to health(TransportHealthState.NOT_IMPLEMENTED)),
            TransportKind.AMNEZIA_WG to (TransportCapabilities.amneziaWg() to health(TransportHealthState.UNKNOWN)),
            TransportKind.XRAY_REALITY to (TransportCapabilities.xrayRealityAdapterShell() to health(TransportHealthState.UNKNOWN)),
        )
        // AMNEZIA_WG and XRAY_REALITY tie on health (UNKNOWN); AMNEZIA_WG's enum ordinal comes first.
        assertEquals(listOf(TransportKind.AMNEZIA_WG, TransportKind.XRAY_REALITY, TransportKind.QUIC), TransportScorer.rank(entries))
    }

    @Test
    fun `rank() with an empty map yields an empty list, never a guess`() {
        assertEquals(emptyList<TransportKind>(), TransportScorer.rank(emptyMap()))
    }
}
