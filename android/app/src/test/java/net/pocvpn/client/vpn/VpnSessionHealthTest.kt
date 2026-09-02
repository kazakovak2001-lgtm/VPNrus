package net.pocvpn.client.vpn

import net.pocvpn.client.relay.RelayReadinessStage
import net.pocvpn.client.relay.RelayedExecutionPlan
import net.pocvpn.client.relay.VpnAttemptContext
import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.transport.TransportKind
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * B25 (task B/M#2/M#3) - pure unit tests of [computeSessionHealth], the ONE
 * function that decides Protected-gating. No coroutines, no transport
 * doubles - see that function's own docs for why this is deliberately a
 * plain file-scope function.
 */
class VpnSessionHealthTest {

    private val plan = RelayedExecutionPlan(
        ingressEndpointId = EndpointId("ru-ingress-1"),
        ingressBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.50", 443),
        ingressTransport = TransportKind.XRAY_REALITY,
        exitEndpointId = EndpointId("germany"),
        exitBinding = EndpointTransportBinding(TransportKind.AMNEZIA_WG, "203.0.113.60", 51820),
        exitTransport = TransportKind.AMNEZIA_WG,
        historyPathId = "ru-ingress-1:XRAY_REALITY->germany:AMNEZIA_WG",
    )

    // --- M#1 - Direct TransportState.Connected behavior is unchanged ---

    @Test
    fun `Direct Connected is always DirectProtected regardless of relayStage`() {
        assertEquals(VpnSessionHealth.DirectProtected, computeSessionHealth(TransportState.Connected, VpnAttemptContext.Direct, null))
        assertEquals(VpnSessionHealth.DirectProtected, computeSessionHealth(TransportState.Connected, VpnAttemptContext.Direct, RelayReadinessStage.END_TO_END_DATA_PLANE_OK))
    }

    // --- M#2 - a relayed ingress-handshake Connected never produces Protected ---

    @Test
    fun `Relayed Connected with no reported stage is RelayHandshake, never Protected`() {
        val health = computeSessionHealth(TransportState.Connected, VpnAttemptContext.Relayed(plan), null)
        assertEquals(VpnSessionHealth.RelayHandshake(RelayReadinessStage.INGRESS_HANDSHAKE_OK), health)
    }

    @Test
    fun `Relayed Connected at every stage below END_TO_END_DATA_PLANE_OK is RelayHandshake, never Protected`() {
        listOf(
            RelayReadinessStage.INGRESS_REACHABLE,
            RelayReadinessStage.INGRESS_HANDSHAKE_OK,
            RelayReadinessStage.UPSTREAM_EXIT_HANDSHAKE_OK,
        ).forEach { stage ->
            val health = computeSessionHealth(TransportState.Connected, VpnAttemptContext.Relayed(plan), stage)
            assertEquals(VpnSessionHealth.RelayHandshake(stage), health)
        }
    }

    // --- M#3 - only END_TO_END_DATA_PLANE_OK produces Protected for a relay ---

    @Test
    fun `Relayed Connected at END_TO_END_DATA_PLANE_OK is RelayProtected`() {
        val health = computeSessionHealth(TransportState.Connected, VpnAttemptContext.Relayed(plan), RelayReadinessStage.END_TO_END_DATA_PLANE_OK)
        assertEquals(VpnSessionHealth.RelayProtected, health)
    }

    // --- every other TransportState is unaffected by attemptContext ---

    @Test
    fun `non-Connected states never depend on attemptContext or relayStage`() {
        val nonConnected = listOf(
            TransportState.Disconnected, TransportState.Connecting, TransportState.Disconnecting,
            TransportState.Reconnecting(1), TransportState.Error("x"), TransportState.HandshakeFailed,
        )
        nonConnected.forEach { state ->
            assertEquals(
                computeSessionHealth(state, VpnAttemptContext.Direct, null),
                computeSessionHealth(state, VpnAttemptContext.Relayed(plan), RelayReadinessStage.END_TO_END_DATA_PLANE_OK),
            )
        }
    }
}
