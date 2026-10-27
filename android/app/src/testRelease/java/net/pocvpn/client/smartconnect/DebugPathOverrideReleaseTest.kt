package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * B57 - runs only under `testReleaseUnitTest` (src/testRelease), against
 * the release build type's own [DebugPathOverride] stub: Auto path
 * selection gets the production attempt list back unchanged (same
 * instance), and there is no status line or action to render or invoke.
 */
class DebugPathOverrideReleaseTest {

    private val binding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 2053)

    @Test
    fun `release returns the production attempt list itself and offers no override`() {
        val direct = AutoGatewaySelector.AutoConnectAttempt.DirectAttempt(
            GatewayAttemptCandidate(
                gatewayId = ProductionGatewayId.STOCKHOLM,
                endpointId = EndpointId("stockholm"),
                transport = TransportKind.XRAY_REALITY,
                region = "test",
                configSnapshot = GatewayConfigSnapshot(
                    endpointHost = "203.0.113.10", endpointPort = "51820", serverPublicKey = "key",
                    clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1", allowedIps = "0.0.0.0/0",
                    profile = AwgProfile.none(),
                ),
                score = 400,
                reasons = listOf("test"),
                transportBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.10", 51820),
            ),
        )
        val relayed = AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt(
            AutoGatewaySelector.RelayAttemptCandidate(
                ingressEndpointId = EndpointId("stockholm-ingress-1"),
                exitEndpointId = EndpointId("frankfurt"),
                ingressTransport = TransportKind.XRAY_REALITY,
                exitTransport = TransportKind.AMNEZIA_WG,
                ingressBinding = binding,
                exitBinding = binding,
                ingressKind = IngressKind.DIRECT_IP,
                ingressRegion = "test", exitRegion = "test",
                score = 100,
                reasons = listOf("test"),
                historyPathId = "stockholm-ingress-1:DIRECT_IP:XRAY_REALITY->frankfurt:AMNEZIA_WG",
            ),
        )
        val attempts = listOf(direct, relayed)

        assertSame(attempts, DebugPathOverride.applyAndConsume(attempts))
        assertSame(attempts, DebugPathOverride.applyAndConsume(attempts))
        assertNull(DebugPathOverride.statusLine())
        assertTrue(DebugPathOverride.actions().isEmpty())
    }
}
