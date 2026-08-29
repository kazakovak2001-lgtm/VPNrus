package net.pocvpn.client.transport

import net.pocvpn.client.smartconnect.TransportSelectionDecision
import net.pocvpn.client.vpn.FakeVpnTransport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B8I1 - RECONCILED narrow tests: TransportOrchestrator is now a pure
 * EXECUTOR of an already-made decision - it must never independently select
 * a transport that conflicts with what it was handed, even when the
 * registry itself would make a different choice possible. Covers this
 * feature's own required case 3.
 */
class TransportOrchestratorTest {

    @Test
    fun `resolving a SelectTransport decision against a registry that has it produces the SAME kind`() {
        val fakeTransport = FakeVpnTransport()
        val registry = TransportRegistry.defaults { fakeTransport }
        val orchestrator = TransportOrchestrator(registry)

        val resolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG))

        assertTrue(resolution is TransportOrchestrator.Resolution.Resolved)
        val resolved = resolution as TransportOrchestrator.Resolution.Resolved
        assertEquals(TransportKind.AMNEZIA_WG, resolved.kind)
        assertEquals(fakeTransport, resolved.transport)
    }

    @Test
    fun `a non-SelectTransport decision is never second-guessed into a substitute choice, even when the registry has an available transport`() {
        val registry = TransportRegistry.defaults { FakeVpnTransport() } // AWG genuinely AVAILABLE here
        val orchestrator = TransportOrchestrator(registry)

        for (decision in listOf(
            TransportSelectionDecision.NoTransportAvailable,
            TransportSelectionDecision.NetworkUnavailable,
            TransportSelectionDecision.UserPolicyBlocked,
            TransportSelectionDecision.ProbeRequired,
        )) {
            val resolution = orchestrator.resolve(decision)
            // Obeys the decision it was GIVEN, never independently falls
            // back to "well AWG is available, use that anyway".
            assertEquals(TransportOrchestrator.Resolution.NotSelectable(decision), resolution)
        }
    }

    @Test
    fun `a decision naming a kind the registry cannot construct fails safe, never substitutes a different kind`() {
        val registry = TransportRegistry.build(emptyList())
        val orchestrator = TransportOrchestrator(registry)

        val resolution = orchestrator.resolve(TransportSelectionDecision.SelectTransport(TransportKind.AMNEZIA_WG))

        assertTrue(resolution is TransportOrchestrator.Resolution.NotSelectable)
    }

    @Test
    fun `candidateOrder reflects only what the registry itself reports available - no independent opinion`() {
        val emptyOrchestrator = TransportOrchestrator(TransportRegistry.build(emptyList()))
        assertTrue(emptyOrchestrator.candidateOrder().isEmpty())

        val withAwg = TransportOrchestrator(TransportRegistry.defaults { FakeVpnTransport() })
        assertEquals(listOf(TransportKind.AMNEZIA_WG), withAwg.candidateOrder())
    }
}
