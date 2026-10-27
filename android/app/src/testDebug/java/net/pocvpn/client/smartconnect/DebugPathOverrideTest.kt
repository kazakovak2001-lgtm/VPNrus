package net.pocvpn.client.smartconnect

import net.pocvpn.client.reachability.EndpointId
import net.pocvpn.client.reachability.EndpointTransportBinding
import net.pocvpn.client.reachability.IngressKind
import net.pocvpn.client.transport.TransportKind
import net.pocvpn.client.vpn.config.AwgProfile
import net.pocvpn.client.vpn.config.GatewayConfigSnapshot
import net.pocvpn.client.vpn.config.ProductionGatewayId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * B57 - runs only under `testDebugUnitTest` (src/testDebug), against the
 * debug build type's own [DebugPathOverride]. Its release counterpart is
 * covered by DebugPathOverrideReleaseTest under src/testRelease.
 */
class DebugPathOverrideTest {

    private val binding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "152.70.43.1", 2053)

    private fun directAttempt(name: String, score: Long) =
        AutoGatewaySelector.AutoConnectAttempt.DirectAttempt(
            GatewayAttemptCandidate(
                gatewayId = ProductionGatewayId.STOCKHOLM,
                endpointId = EndpointId(name),
                transport = TransportKind.XRAY_REALITY,
                region = "test",
                configSnapshot = GatewayConfigSnapshot(
                    endpointHost = "203.0.113.10", endpointPort = "51820", serverPublicKey = "key",
                    clientTunnelIp = "10.77.0.2", gatewayTunnelIp = "10.77.0.1", allowedIps = "0.0.0.0/0",
                    profile = AwgProfile.none(),
                ),
                score = score,
                reasons = listOf("test"),
                transportBinding = EndpointTransportBinding(TransportKind.XRAY_REALITY, "203.0.113.10", 51820),
            ),
        )

    private fun relayedAttempt(name: String, score: Long) =
        AutoGatewaySelector.AutoConnectAttempt.RelayedAttempt(
            AutoGatewaySelector.RelayAttemptCandidate(
                ingressEndpointId = EndpointId(name),
                exitEndpointId = EndpointId("frankfurt"),
                ingressTransport = TransportKind.XRAY_REALITY,
                exitTransport = TransportKind.AMNEZIA_WG,
                ingressBinding = binding,
                exitBinding = binding,
                ingressKind = IngressKind.DIRECT_IP,
                ingressRegion = "test", exitRegion = "test",
                score = score,
                reasons = listOf("test"),
                historyPathId = "$name:DIRECT_IP:XRAY_REALITY->frankfurt:AMNEZIA_WG",
            ),
        )

    @Before
    fun resetToAuto() {
        DebugPathOverride.clear()
    }

    @Test
    fun `AUTO returns the production attempt list itself`() {
        val attempts = listOf(directAttempt("stockholm", 300), relayedAttempt("stockholm-ingress-1", 100))

        assertSame(attempts, DebugPathOverride.applyAndConsume(attempts))
    }

    @Test
    fun `RELAYED keeps only the Relayed attempts, in production order and untouched`() {
        val r1 = relayedAttempt("stockholm-ingress-1", 200)
        val r2 = relayedAttempt("other-ingress", 50)
        val attempts = listOf(directAttempt("stockholm", 400), r1, directAttempt("frankfurt", 300), r2)
        DebugPathOverride.forceRelayed()

        val result = DebugPathOverride.applyAndConsume(attempts)

        assertEquals(listOf(r1, r2), result)
        assertSame(r1, result[0])
        assertEquals(200L, result[0].score)
    }

    @Test
    fun `RELAYED is one-shot - the next connect gets the production list again`() {
        val attempts = listOf(directAttempt("stockholm", 400), relayedAttempt("stockholm-ingress-1", 100))
        DebugPathOverride.forceRelayed()
        DebugPathOverride.applyAndConsume(attempts)

        assertSame(attempts, DebugPathOverride.applyAndConsume(attempts))
        assertTrue(DebugPathOverride.statusLine()!!.startsWith("Path preference: AUTO (debug only)"))
    }

    @Test
    fun `RELAYED with no Relayed attempt fails closed instead of falling back to Direct`() {
        DebugPathOverride.forceRelayed()

        val result = DebugPathOverride.applyAndConsume(listOf(directAttempt("stockholm", 400)))

        assertTrue(result.isEmpty())
        assertTrue(DebugPathOverride.statusLine()!!.endsWith("last forced connect kept: none (fail-closed)"))
    }

    @Test
    fun `status line shows the pending override and the relay path the forced connect kept`() {
        DebugPathOverride.forceRelayed()
        assertTrue(DebugPathOverride.statusLine()!!.startsWith("Path preference: RELAYED"))

        DebugPathOverride.applyAndConsume(listOf(directAttempt("stockholm", 400), relayedAttempt("stockholm-ingress-1", 100)))

        assertTrue(
            DebugPathOverride.statusLine()!!.endsWith(
                "last forced connect kept: stockholm-ingress-1:DIRECT_IP:XRAY_REALITY->frankfurt:AMNEZIA_WG",
            ),
        )
    }

    @Test
    fun `actions force RELAYED and clear back to AUTO`() {
        val actions = DebugPathOverride.actions().toMap()
        val attempts = listOf(directAttempt("stockholm", 400), relayedAttempt("stockholm-ingress-1", 100))

        actions.getValue("Force Path RELAYED on next Auto connect").invoke()
        actions.getValue("Clear path force / AUTO").invoke()

        assertSame(attempts, DebugPathOverride.applyAndConsume(attempts))
    }
}
